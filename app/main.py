"""Self-hosted DevOps config portal."""
import anyio
import asyncio
import websockets
import codecs
import contextlib
import datetime as dt
import io
import json
import os
import re
import shutil
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

from fastapi import (Body, FastAPI, File, Form, HTTPException, Query, Request,
                     UploadFile, WebSocket, WebSocketDisconnect)
from starlette.background import BackgroundTask
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, RedirectResponse, Response,
                               StreamingResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context

from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from . import (ansible, answers, assets, assistant, auth, bmc, cbase, certs,
               csvsafe, csp, grafana, grafview,
               passkeys,
               charts, ci,
               warmer,
    logos,
    aiuser,
    aitools,
    agent,
               cloud, selfupdate,
               cloudops, dbconn, edge, invite, mailer,
               snapshot, updates, vpn,
               compare,
               config,
               diagram, fleet, gather, gitops, virt, workflows,
               access, audit, cluster as clusterview, env, kmanage, layout,
               tools,
               git_ops, gitrepo, history, kube, logs, logstore, monitoring,
               rbac, repo, sealing, search, security, sso, spend, stordev, store,
               expiry,
               pam, webseat,
               actions,
               mcp,
               terraform,
               provision,
               summary,
               svcview,
               timeline,
               topology)

BASE = Path(__file__).resolve().parent.parent
# How much of guacd's stream is taken per read. See the relays below.
GUAC_READ = 262144


app = FastAPI(title=store.brand()["name"], root_path=env.ROOT_PATH)
templates = Jinja2Templates(directory=str(BASE / "templates"))

# Compression. The backend renders a page in 2-3ms; what a person FELT as lag
# was 230kB of uncompressed HTML per navigation, so the wire is where the time
# went. Verified against this starlette's source before trusting it with the
# live streams: its gzip responder passes text/event-stream through untouched,
# so the log follow and the run window still deliver each event as it happens
# rather than when the compressor feels full.
from starlette.middleware.gzip import GZipMiddleware  # noqa: E402
app.add_middleware(GZipMiddleware, minimum_size=1024)

# The stylesheet and the terminal emulator live here. The stylesheet used to be
# inline in base.html — most of every page's weight, re-parsed per click — and
# is now fetched once per release: every reference carries ?v=<version>, so the
# year-long cache below can never serve a stale sheet to a new build.
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")


@app.middleware("http")
async def _security_headers(request, call_next):
    """Mint the request's nonce, and put the policy on the way out.

    It wraps everything because the nonce has to exist BEFORE any template
    renders, and the header has to be on the response whatever produced it —
    a route, an error page, or a redirect that a browser will follow to a page
    this middleware then covers anyway.

    Static files are skipped: they are served with a year-long immutable
    cache, so a per-request nonce baked into one would be wrong for every
    later request that gets the cached copy.
    """
    csp.new_nonce()
    response = await call_next(request)
    if not request.url.path.startswith("/static/"):
        response.headers["Content-Security-Policy"] = csp.policy()
        for name, value in csp.COMPANIONS.items():
            response.headers[name] = value
    return response


@app.middleware("http")
async def _immutable_static(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/") and response.status_code == 200:
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@app.get("/icons/logos.svg", include_in_schema=False)
def logos_sprite():
    """Every vendor mark, once, for the whole session.

    Served from /icons rather than /assets: /assets is already the Server
    assets area's own prefix, and putting this under it meant adding "/assets"
    to rbac.ALWAYS — which made area_for_path return None for the whole
    hardware inventory and handed it to anybody signed in. A static asset must
    never share a prefix with a governed page.

    Outside /static because it is built from app/logodata.py rather than kept
    as a second copy on disk — one file to rebuild, not two, and no way for the
    two to disagree. Immutable for a day: the marks only change when the image
    does, and a stale one is a wrong logo rather than wrong data.
    """
    return Response(logos.sprite(), media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})

# paths reachable without a session
# /healthz is open because a kubelet probe carries no session and must not be
# redirected to a login page — it answers with the version and nothing else.
OPEN_PATHS = ("/login", "/bootstrap", "/mfa", "/logout", "/favicon.ico",
              # an invitation is opened by somebody with no account yet, and a
              # reset by somebody who cannot sign in — neither can sit behind
              # the sign-in they exist to make possible
              "/invite", "/reset", "/forgot",
              "/healthz", "/static", "/icons", "/auth/microsoft")
# reachable even when an ended trial has locked everything else
# "/me", not "/profile": the account page has always been at /me, so a locked
# install was also refusing people their own password and MFA settings


def current_user(request: Request) -> dict | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    u = auth.by_id(uid)
    if not u or u.get("disabled"):
        return None
    if not u.get("mfa_enrolled") or not request.session.get("mfa_ok"):
        return None
    return u


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    # MCP is a machine door, so it is answered like one: a bearer token instead
    # of a session, and a JSON refusal instead of a redirect to a login page no
    # AI client can read. It is HERE rather than in the route so the
    # lock, the role check and the audit stay in the one place that enforces
    # them for every other path.
    if path == "/mcp" or path.startswith("/mcp/"):
        return await _mcp_door(request, call_next)
    if path.startswith(OPEN_PATHS):
        return await call_next(request)
    if not auth.any_users():
        return RedirectResponse("/bootstrap", 303)
    uid = request.session.get("uid")
    if uid:
        u = auth.by_id(uid)
        if u and not u.get("disabled"):
            if not u.get("mfa_enrolled"):
                return RedirectResponse("/mfa/setup", 303)
            if not request.session.get("mfa_ok"):
                return RedirectResponse("/mfa", 303)
            request.state.user = u
            # Recorded here because this is the one place that has already
            # resolved a user on every request. The warmer keeps the timeline
            # and the expiry radar warm for whoever is actually signing in.
            warmer.note_view("user", u.get("id"))
            # Roles decide what this person may reach. Hiding a link is
            # presentation; this is the check that actually refuses, and it
            # reads the same functions the sidebar does, so a hidden page is a
            # forbidden one rather than merely an unadvertised one.
            # Privileged Access is switched on in Settings. While it is off its
            # pages do not exist for anyone — the code stays in the tree, but
            # nothing in the running product reaches it.
            #
            # /settings/pam is DELIBERATELY NOT in that list. It used to be,
            # which was correct while the switch was an environment variable
            # and wrong the moment the switch moved onto that page: hiding it
            # would hide the only way to turn the feature back on. It carries
            # the `settings` area like every other settings page, so who may
            # reach it is already answered.
            if not pam.enabled() and (path == "/pam" or path.startswith("/pam/")):
                return RedirectResponse("/", 303)
            area = rbac.area_for_path(path)
            if area and not rbac.may_area(u, area):
                label = rbac.AREAS[area][0]
                if _wants_json(request):
                    return JSONResponse(
                        {"error": f"your roles do not include {label}"},
                        status_code=403)
                return templates.TemplateResponse(
                    request, "denied.html",
                    {"request": request, "status": None, "me": u,
                     "area": label,
                     "brand": store.brand, "nav_projects": nav_projects},
                    status_code=403)
            # Recorded after the RBAC check rather than beside area_for_path,
            # so a page somebody was refused is not one the warmer then polls
            # somebody else's Prometheus for every thirty-five seconds.
            warmer.note_view("page", area)
            return await call_next(request)
    return RedirectResponse(f"/login?next={path}", 303)


def _mcp_json(payload: dict, status: int = 200, **headers) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers=headers or None)


async def _mcp_door(request: Request, call_next):
    """Authenticate an MCP request, or refuse it in a language a client reads.

    A session cookie also works — which is what makes the endpoint testable
    from a browser — but a bearer token is the contract, and its absence is a
    401 with the challenge rather than a 303 to /login.
    """
    if not mcp.enabled():
        # Not 403: an installation that has not turned this on has no MCP
        # endpoint at all, and saying "forbidden" would advertise one.
        return _mcp_json({"error": "this portal does not serve MCP"}, 404)
    head = request.headers.get("authorization") or ""
    user = None
    tok = {}
    if head[:7].lower() == "bearer ":
        got = mcp.resolve(head[7:])
        if not got:
            auth.audit(None, "mcp_denied", "token",
                       "unknown, revoked or expired token", _client_ip(request))
            return _mcp_json(
                {"error": "that token is not valid — it may have been revoked "
                          "or expired"}, 401,
                **{"WWW-Authenticate": "Bearer realm=\"mcp\""})
        user, tok = got["user"], got["token"]
    elif request.session.get("uid"):
        user = current_user(request)
    if not user:
        return _mcp_json({"error": "an MCP client must present a bearer token"},
                         401, **{"WWW-Authenticate": "Bearer realm=\"mcp\""})
    if not rbac.may_area(user, "mcp"):
        auth.audit(user, "mcp_denied", "connect",
                   "the account does not hold MCP access", _client_ip(request))
        return _mcp_json(
            {"error": "your roles do not include MCP access"}, 403)
    request.state.user = user
    request.state.mcp_token = tok
    if tok:
        mcp.touch(tok["id"], _client_ip(request))
    return await call_next(request)


def _wants_json(request: Request) -> bool:
    """Would this caller rather have JSON than a redirect?

    Checked on both headers: the assistant widget sends Content-Type
    application/json with Accept */*, so accepting alone missed it and a locked
    portal answered its fetch with a login page.
    """
    return (request.headers.get("accept", "").startswith("application/json")
            or "application/json" in request.headers.get("content-type", "")
            or request.headers.get("x-requested-with") == "XMLHttpRequest")


def hue(name: str) -> int:
    return sum(ord(c) * 7 for c in name) % 360


_MD_URL = re.compile(r"https?://[^\s<>\"']+")


def _mdlite(text) -> "Markup":
    """Markdown-lite for platform-authored text (a DefectDojo description, a
    Trivy advisory): escape EVERYTHING first, then turn the handful of shapes
    scanners actually emit — headings, **bold**, `code`, ``` fences, bullet
    lists, bare links — into HTML. Deliberately not a markdown engine: the
    escape-first order is what makes it safe to render other systems' text."""
    from markupsafe import Markup, escape

    def inline(s: str) -> str:
        s = str(escape(s))
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)

        def link(m):
            url = m.group(0).rstrip(".,;:)")   # prose punctuation, not the URL
            tail = m.group(0)[len(url):]
            return (f'<a href="{url}" target="_blank" rel="noopener">{url}</a>'
                    f"{tail}")
        return _MD_URL.sub(link, s)

    out, para, items, code = [], [], [], None
    def flush():
        if items:
            out.append("<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>")
            items.clear()
        if para:
            out.append("<p>" + "<br>".join(para) + "</p>")
            para.clear()
    for line in str(text or "").replace("\r\n", "\n").split("\n"):
        stripped = line.strip()
        if stripped.startswith("```"):
            if code is None:
                flush()
                code = []
            else:
                out.append("<pre>" + str(escape("\n".join(code))) + "</pre>")
                code = None
            continue
        if code is not None:
            code.append(line)
            continue
        if not stripped:
            flush()
            continue
        m = re.match(r"^#{1,4}\s+(.*)", stripped)
        if m:
            flush()
            out.append(f"<h5>{inline(m.group(1))}</h5>")
            continue
        m = re.match(r"^[-*•]\s+(.*)", stripped)
        if m:
            if para:
                flush()
            items.append(inline(m.group(1)))
            continue
        if items:
            flush()
        para.append(inline(stripped))
    if code is not None:                       # an unclosed fence is still code
        out.append("<pre>" + str(escape("\n".join(code))) + "</pre>")
    flush()
    return Markup("".join(out))


def nav_projects():
    return [{"id": pid, "name": p.get("name", ""), "icon": p.get("icon", "📦")}
            for pid, p in store.projects().items()]


# Naming is per project, so these three read the current project out of the
# render context rather than taking it as an argument — every template can keep
# calling env_label(env) / service_display(f) and still get that project's rules.
def _conv(c) -> dict:
    return c.get("project") or {}


@pass_context
def t_env_label(c, env):
    return config.resolve_env(env, _conv(c).get("env_aliases"))


@pass_context
def t_env_glyph(c, env, size: int = 22):
    """The line icon for an environment, already rendered."""
    return logos.glyph(config.env_glyph(env, _conv(c).get("env_aliases")), size)


@pass_context
def t_service_display(c, fname):
    conv = _conv(c)
    return repo.display_name(fname, tuple(conv.get("strip_suffixes") or ()),
                             (conv.get("layout_pattern") or "").strip())


@pass_context
def t_may(c, area):
    """Whether the signed-in person's roles grant this area.

    A template global rather than a ctx() key: the sidebar renders on every
    page, including the handful of routes that build their context by hand, and
    a missing `may` there is a 500 rather than a hidden link. Reads
    request.state.user, which the auth middleware has already set.
    """
    request = c.get("request")
    user = getattr(request.state, "user", None) if request else None
    return rbac.may_area(user, area)


@pass_context
@pass_context
def t_assistant_has_model(c):
    return assistant.ready()


@pass_context
def t_assistant_model(c):
    return assistant.config()["model"] if assistant.ready() else ""


def _update_ready() -> bool:
    """Is a newer release known about? For the dot beside the version.

    Called on every render. peek() reads a cache and a few rows, which is
    cheap — but "cheap" is not "cannot fail", and a version badge is not worth
    a 500 on a page somebody needs.
    """
    try:
        return bool(updates.peek().get("available"))
    except Exception:                                          # noqa: BLE001
        return False


# Every provider entry learns its own id, so a template holding the dict can
# ask for the mark without knowing what the surrounding loop called things.
logos.register(gitops, ci, security, monitoring, workflows, virt, vpn, edge,
               bmc, logstore, cloud, dbconn, stordev)

templates.env.globals.update(
    may=t_may, pam_enabled=pam.enabled,
    # the widget renders on every page, so these are globals rather than
    # something each of 148 routes has to remember to pass
    assistant_has_model=t_assistant_has_model,
    assistant_model=t_assistant_model,
    service_display=t_service_display, hue=hue,
    summary=repo.service_summary, env_glyph=t_env_glyph,
    env_label=t_env_label, flag_for=config.flag_for,
    nav_projects=nav_projects, weather=ci.weather, brand=store.brand,
    # The sidebar draws the running version on every page. In ctx() it was
    # missing from the four sidebar pages that build their context by hand —
    # Compare, Search, the wizard and the denied page — and the pill rendered
    # empty on exactly those. A global cannot be forgotten by a route.
    portal_version=lambda: env.VERSION, update_ready=_update_ready,
    severities=security.SEVERITIES, risk_grade=security.risk_grade,
    severities_mon=monitoring.SEVERITIES,
    donut=charts.donut, ring=charts.ring, gauge=charts.gauge,
    sparkline=charts.sparkline,
    hbars=charts.hbars, stack=charts.stack, load_color=charts.load_color,
    histogram=charts.histogram,
    # Marks and line icons. Globals for the same reason the version pill is:
    # the sidebar draws icons on every page, and a route cannot forget these.
    logo=logos.logo, plogo=logos.plogo, glyph=logos.glyph,
    # the two shortcuts in the top bar; free, see _cluster_choices
    # a lambda because the helper is defined further down the file, and a
    # global is resolved when the template calls it rather than now
    quick_clusters=lambda: _cluster_choices(),
    project_icon=logos.project_icon,
    # Every inline <script> carries this request's nonce or the browser
    # refuses to run it. A global, not a ctx() key, for the same reason
    # the version pill is one — and here a route that forgot it would
    # ship a page whose scripts silently do nothing.
    csp_nonce=csp.nonce,
)
# a filter, not a global: `text | mdlite` reads as what it is — a rendering of
# the text — and composes with the rest of a template expression
templates.env.filters["mdlite"] = _mdlite


# Names base.html binds for itself. A context value under one of these is
# silently shadowed inside every child block, and the failure never points at
# the cause.
#
# Macros were the first way this bit: a console link rendered as
# "<Macro \'link\'>", navigated to a URL containing that text and earned "The
# specified InstanceId does not exist" from Alibaba. One name, three symptoms.
#
# `{% set %}` is the second, and it is worse because it looks local. A loop
# variable in the top bar called `ns` shadowed the Kubernetes namespace the
# cluster page passes under that name; the page fed a Jinja Namespace object to
# |tojson and answered 500 from a line three templates away. It had also been
#
# Both are read from the template rather than listed here, so adding either
# cannot get out of step with this.
def _base_names() -> set:
    try:
        text = (BASE / "templates" / "base.html").read_text()
    except OSError:
        return {"link"}
    found = set(re.findall(r"{%-?\s*macro\s+([A-Za-z_][A-Za-z0-9_]*)", text))
    # Only plain `set x = ...`; `set ns.field = ...` binds nothing new, and a
    # {% set %}…{% endset %} block is the same name-binding either way.
    found |= set(re.findall(r"{%-?\s*set\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", text))
    return found or {"link"}


SHADOWED = _base_names()

# Keys ctx() sets for base.html's own chrome. A route passing one of these wins,
# because **extra lands last — and the failure surfaces as a template error deep
# inside base.html rather than at the call that caused it. A page filter called
# "status" replaced the git status and broke the header; now it says so here.
# region and me are absent deliberately: some routes override those on purpose.
RESERVED = {"request", "project", "pname", "rname", "status"}


def ctx(request: Request, pid: str = "", rgid: str = "", **extra):
    if (clash := SHADOWED & set(extra)):
        raise RuntimeError(
            f"context key(s) {sorted(clash)} are bound by base.html (a macro "
            f"or a top-level {{% set %}}) and would be shadowed inside every "
            f"block — rename one of them")
    if (clash := RESERVED & set(extra)):
        raise RuntimeError(
            f"context key(s) {sorted(clash)} are set by ctx() for base.html and "
            f"would be overwritten — rename them (e.g. status -> status_filter)")
    extra.setdefault("me", getattr(request.state, "user", None))
    project = store.get_project(pid) if pid else None
    region = store.get_region(pid, rgid) if (pid and rgid) else None
    return {"request": request, "pid": pid, "rgid": rgid,
            "project": project, "region": region,
            "pname": (project or {}).get("name", ""),
            "rname": (region or {}).get("name", ""),
            "status": _repo_badge(pid, rgid),
            **extra}




def _repo_badge(pid: str, rgid: str):
    """The repo state for the top bar, and a nudge when it is behind.

    The badge said "out of date · Sync now" and nothing else, so a reader had no
    way to tell a region the timer is about to fetch from one it cannot — and the
    automatic pass runs on a five-minute cadence whose first tick is at startup,
    before anybody has opened anything. Landing on a stale region therefore meant
    up to five minutes of a page insisting it was out of date while a sync was in
    fact coming.

    So: ask for it now (the warmer decides when, and never blocks this render),
    and hand the template what the last automatic attempt actually did, so the
    badge can say "syncing" or "held — uncommitted changes" rather than implying
    nothing is happening.
    """
    if not (pid and rgid):
        return None
    st = git_ops.region_status(pid, rgid)
    st["auto"] = warmer.repo_state(rgid)
    if st.get("stale") and not st.get("dirty"):
        warmer.sync_soon(pid, rgid)
        st["syncing"] = True
    return st


def _csv(raw) -> list:
    """Comma- or newline-separated form field to a clean list."""
    return [x.strip() for x in re.split(r"[,\n]", str(raw or "")) if x.strip()]


def _pairs(raw) -> dict:
    """`a=b, c=d` to {a: b, c: d}. Entries without '=' are ignored rather than
    guessed at."""
    out = {}
    for item in _csv(raw):
        if "=" in item:
            k, v = item.split("=", 1)
            if k.strip() and v.strip():
                out[k.strip()] = v.strip()
    return out


def back(msg: str = "", err: str = "", anchor: str = "",
         to: str = "/settings") -> RedirectResponse:
    """Redirect somewhere with something to say.

    The separator is chosen rather than assumed: a `to` that already carries a
    query string used to gain a second '?', which silently swallowed the
    message and corrupted the last parameter before it. The values are encoded
    for the same reason — a message containing '&' would otherwise cut itself
    in half and invent a parameter.
    """
    q = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    url = to
    if q:
        url += ("&" if "?" in to else "?") + urllib.parse.urlencode(q)
    return RedirectResponse(url + (f"#{anchor}" if anchor else ""), 303)


def _board_data(want: set) -> dict:
    """Only what the visible panels asked for.

    Lifted out of the route so one panel can be rebuilt on its own: a
    panel with its own refresh interval needs a way to fetch just itself,
    and without this it would have had to reload the whole page — which
    would defeat the point of giving one panel a slower or faster rate.
    """
    data = {}

    if "fleet" in want or "trend" in want or "agg" in want:
        # never force here: mark_stale() above already asked for a rebuild, and
        # forcing would make the caller wait for it — which is the whole point of
        # not forcing
        f = fleet.overview()
        data["fleet"] = f
        if "trend" in want:
            data["trend"] = {
                "bad": history.series("", "bad"),
                "pods": history.series("", "pods"),
                "cpu": {c["cid"]: history.series(c["cid"], "cpu")
                        for c in f["clusters"]},
                "mem": {c["cid"]: history.series(c["cid"], "mem")
                        for c in f["clusters"]},
                "span": history.span(), "n": history.samples(),
            }
        if "agg" in want:
            # fleet-wide utilisation: pooled capacity, not an average of
            # percentages, which would let a small cluster distort the picture
            live = [c for c in f["clusters"] if c["reachable"] and c["cpu"]]

            def _pool(kind):
                used = sum(c[kind]["used"] for c in live)
                cap = sum(c[kind]["cap"] for c in live)
                return {"used": used, "cap": cap,
                        "pct": round(used / cap * 100, 1) if cap else 0.0}
            data["agg"] = {"cpu": _pool("cpu"), "mem": _pool("mem"),
                           "sources": sorted({c["cpu"]["source"]
                                              for c in live}) or ["—"]}
    if "pipes" in want:
        data["pipes"] = summary.pipelines()
    if "sec" in want:
        data["sec"] = summary.security_roll()
    if "alerts" in want:
        data["alerts"] = _alerts_roll()
    if "assets" in want:
        data["assets"] = assets.stats()
    if "spend" in want:
        data["spend"] = spend.stats()
    if "repos" in want:
        data["repos"] = _repo_roll()
    if "activity" in want:
        data["activity"] = auth.read_audit(12)
    if "logs" in want:
        data["logs"] = _logs_roll()
    if "wf" in want:
        data["wf"] = _wf_roll()
    if "gitops" in want:
        data["gitops"] = _gitops_roll()
    if "virt" in want:
        data["virt"] = _virt_roll()
    if "dbs" in want:
        data["dbs"] = _dbs_roll()
    return data


# ── landing ────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home(request: Request, refresh: str = "", arrange: str = ""):
    """The Overview, assembled from whatever panels this person has arranged.

    Only the data the visible panels declare is built, so a page with three
    panels does three panels' worth of work.
    """
    if refresh:
        # ask for fresh data, do not block on it: the snapshot the page already
        # has is still true, only older, and the background refresh replaces it
        # in a second or two. A blocking refresh made this button feel broken.
        fleet.mark_stale()
        summary.invalidate()
    me = getattr(request.state, "user", None)
    uid = (me or {}).get("id", "")
    panels = layout.get(uid)
    want = layout.needs(panels)
    data = _board_data(want)

    return templates.TemplateResponse(
        request, "home.html",
        ctx(request, panels=panels, catalogue=layout.CATALOGUE,
            spare=layout.available(panels), widths=layout.WIDTHS,
            heights=layout.HEIGHTS, refreshes=layout.REFRESH,
            arrange=bool(arrange), d=data,
            fleet=data.get("fleet"), trend=data.get("trend"),
            agg=data.get("agg"), pipes=data.get("pipes"), sec=data.get("sec")))


# ── the whole fleet: nodes and pods on one page each ──────────
@app.get("/nodes", response_class=HTMLResponse)
def fleet_nodes(request: Request, cluster: str = "", q: str = "",
                problems: str = "", refresh: str = ""):
    """Every node in every cluster, one table. The tiles on the Overview link
    here — the question they answer ("47/48 ready — which one?") should be one
    click from its answer."""
    got = clusterview.everywhere("nodes", refresh=bool(refresh))
    groups = [{"pid": g["pid"], "project": g["project"], "cid": g["cid"],
               "cluster": g["cluster"]} for g in got]
    broken = [g for g in got if g.get("error")]
    rows, needle = [], q.strip().lower()
    # A dict check per cluster, not per pod: writable() reads a stored field, so
    # this costs nothing, but doing it inside the pod loop would repeat it eight
    # hundred times for no reason.
    for g in got:
        if cluster and g["cid"] != cluster:
            continue
        for n in g.get("nodes") or []:
            if problems and n["ready"] and n["schedulable"] and not n["pressure"]:
                continue
            if needle and needle not in " ".join(
                    [n["name"], g["cluster"], g["project"], n["version"],
                     " ".join(n["roles"])]).lower():
                continue
            rows.append({**n, "pid": g["pid"], "project": g["project"],
                         "cid": g["cid"], "cluster": g["cluster"]})
    rows.sort(key=lambda n: (n["ready"], n["project"], n["cluster"], n["name"]))
    return templates.TemplateResponse(
        request, "fleet_nodes.html",
        ctx(request, rows=rows, groups=groups, broken=broken,
            want_cluster=cluster, q=q, problems=bool(problems),
            # Clusters whose read did not land inside the first paint. Named on
            # the page rather than waited for: a fleet table showing "0
            # clusters" with no explanation is worse than one that is honest
            # about still filling in.
            pending=clusterview.pending_clusters("nodes")))


@app.get("/pods", response_class=HTMLResponse)
def fleet_pods(request: Request, cluster: str = "", q: str = "",
               attention: str = "", refresh: str = ""):
    """Every pod in every cluster — worst first, capped for the browser's sake
    but counted in full. ?attention=1 is the "pods needing attention" tile."""
    got = clusterview.everywhere("pods", refresh=bool(refresh))
    groups = [{"pid": g["pid"], "project": g["project"], "cid": g["cid"],
               "cluster": g["cluster"]} for g in got]
    broken = [g for g in got if g.get("error")]
    # Once per cluster, not once per pod: writable() reads a stored field, so it
    # is free — but eight hundred pods would ask eight hundred times.
    can_manage = bool(_may(request, "manage"))
    manageable = {g["cid"]: bool(can_manage and kmanage.writable(
        store.get_cluster(g["pid"], g["cid"]) or {})) for g in got}
    rows, needle = [], q.strip().lower()
    for g in got:
        if cluster and g["cid"] != cluster:
            continue
        for pd in g.get("pods") or []:
            if attention and pd["healthy"]:
                continue
            if needle and needle not in " ".join(
                    [pd["name"], pd["namespace"], pd["node"], g["cluster"],
                     g["project"], " ".join(pd["images"])]).lower():
                continue
            rows.append({**pd, "pid": g["pid"], "project": g["project"],
                         "cid": g["cid"], "cluster": g["cluster"],
                         # whether THIS cluster would accept a shell, so the
                         # row can offer the same actions the cluster page does
                         "manage": manageable.get(g["cid"], False)})
    rows.sort(key=lambda pd: (pd["healthy"], -pd["restarts"],
                              pd["namespace"], pd["name"]))
    CAP = 800   # a browser table, not an export — the worst rows come first
    return templates.TemplateResponse(
        request, "fleet_pods.html",
        ctx(request, shown=rows[:CAP], total=len(rows), groups=groups,
            broken=broken, want_cluster=cluster, q=q,
            attention=bool(attention),
            pending=clusterview.pending_clusters("pods")))


@app.post("/overview/layout")
async def overview_layout(request: Request):
    """Save this person's panel arrangement, or reset it."""
    me = getattr(request.state, "user", None)
    uid = (me or {}).get("id", "")
    body = await request.json()
    if body.get("reset"):
        return JSONResponse({"panels": layout.reset(uid)})
    return JSONResponse({"panels": layout.save(uid, body.get("panels"))})


def _alerts_roll() -> dict:
    """What is firing across the monitoring systems, or why it is unknown."""
    conns = store.all_mon()
    if not conns:
        return {"conns": 0, "counts": {}, "total": 0, "broken": [], "alerts": []}
    got = fleet._pmap(lambda c: (c, monitoring.overview(c)), conns,
                      workers=min(5, len(conns)))
    counts, broken, alerts = {}, [], []
    for pair in got:
        if not pair:
            continue
        c, o = pair
        if not o or o.get("error"):
            broken.append(c.get("name", "?"))
            continue
        counts = monitoring.merge_counts(counts, o.get("counts") or {})
        alerts += (o.get("alerts") or [])[:5]
    order = {s: i for i, s in enumerate(monitoring.SEVERITIES)}
    alerts.sort(key=lambda a: order.get(a.get("severity"), 9))
    return {"conns": len(conns), "counts": counts,
            "total": sum(counts.values()), "broken": broken,
            "alerts": alerts[:6]}


def _region_repo_groups(pid: str, rgid: str) -> list[dict]:
    """A region's environments grouped by the (repository, branch) they read.

    THE unit every repository listing works in now: a region can span several
    repositories, and several environments usually share one — so a repository
    row is a group of environments, never a region and never one env. Status
    is read once per group from the shared checkout.
    """
    envs = repo.list_envs(pid, rgid, include_hidden=True)
    groups: dict[tuple, dict] = {}
    for env, files in envs.items():
        b = repo.binding(pid, rgid, env)
        g = groups.setdefault((b["url"], b["branch"]), {
            "url": b["url"], "branch": b["branch"], "envs": [],
            "files": 0, "auth": False, "first": env})
        g["envs"].append(env)
        g["files"] += len(files)
        g["auth"] = g["auth"] or b["has_own_auth"]
    out = []
    for g in groups.values():
        g["git"] = gitrepo.head_info(pid, rgid, env_name=g["first"]) \
            if g["url"] else {"cloned": False, "branch": "-", "dirty": "",
                              "head": "no repository", "sha": "",
                              "subject": "", "author": "", "when": ""}
        out.append(g)
    return sorted(out, key=lambda g: (g["url"], g["branch"]))


def _repo_roll() -> list:
    """Clone state per (repository, branch) — cheap, all local git reads."""
    out = []
    for pid, p in store.projects().items():
        for rgid, rg in (p.get("regions") or {}).items():
            for g in _region_repo_groups(pid, rgid):
                if not g["url"]:
                    continue
                st = git_ops.region_status(pid, rgid, env=g["first"])
                out.append({
                    "project": p.get("name", ""), "icon": p.get("icon", "📦"),
                    "region": rg.get("name", ""), "branch": st.get("branch", ""),
                    "head": st.get("head", ""), "stale": bool(st.get("stale")),
                    "dirty": len(git_ops.dirty_paths(pid, rgid, env=g["first"])),
                    "url": f"/repos#{rgid}",
                })
    return out


def _wf_roll() -> dict:
    """What is running and what has failed across the workflow engines.

    Each engine is read in parallel and a failure is carried rather than raised:
    one unreachable Temporal must not blank the panel for the others.
    """
    conns = store.all_wf()
    if not conns:
        return {"conns": 0, "engines": []}

    def one(c):
        base = {"name": c.get("name", "?"), "type": c.get("type", ""),
                "unit": "group", "running": 0, "failed": 0, "groups": [],
                "error": ""}
        try:
            o = workflows.overview(c)
            base.update({"unit": o.get("unit", "group"),
                         "running": o.get("running", 0),
                         "failed": o.get("failed", 0),
                         "groups": [{"name": g["name"], "running": g["running"],
                                     "failed": g["failed"]}
                                    for g in o.get("groups", [])]})
        except Exception as e:                                # noqa: BLE001
            base["error"] = str(e)[:120]
        return base
    got = [g for g in fleet._pmap(one, conns, workers=min(4, len(conns))) if g]
    return {"conns": len(conns), "engines": got,
            "running": sum(g["running"] for g in got),
            "failed": sum(g["failed"] for g in got)}


def _gitops_roll() -> dict:
    """Argo CD applications by sync and health.

    Out-of-sync is not the same as unhealthy and both are worth seeing: an app
    can be perfectly healthy while running something other than what is in git,
    which is the state that surprises people during an incident.
    """
    conns = store.all_gitops()
    if not conns:
        return {"conns": 0, "sites": []}

    def one(c):
        base = {"name": c.get("name", "?"), "apps": 0, "synced": 0,
                "outofsync": 0, "healthy": 0, "degraded": 0, "error": ""}
        try:
            for a in gitops.apps(c):
                base["apps"] += 1
                sync = str(a.get("sync") or a.get("sync_status") or "").lower()
                health = str(a.get("health") or a.get("health_status") or "").lower()
                if "synced" in sync and "out" not in sync:
                    base["synced"] += 1
                elif sync:
                    base["outofsync"] += 1
                if "healthy" in health:
                    base["healthy"] += 1
                elif health in ("degraded", "missing", "unknown") or "degrad" in health:
                    base["degraded"] += 1
        except Exception as e:                                # noqa: BLE001
            base["error"] = str(e)[:120]
        return base
    got = [g for g in fleet._pmap(one, conns, workers=min(4, len(conns))) if g]
    return {"conns": len(conns), "sites": got,
            "apps": sum(g["apps"] for g in got),
            "outofsync": sum(g["outofsync"] for g in got),
            "degraded": sum(g["degraded"] for g in got)}


def _virt_roll() -> dict:
    """Hypervisors: hosts, and how many guests are running."""
    conns = store.all_virt()
    if not conns:
        return {"conns": 0, "sites": []}

    def one(c):
        base = {"name": c.get("name", "?"), "type": c.get("type", ""),
                "hosts": 0, "vms": 0, "on": 0, "off": 0, "error": ""}
        try:
            got = virt.read(c)
            # `guests`, not `vms`: read() has never returned a "vms" key, so
            # this panel silently reported an empty estate since it was built
            vms = got.get("guests") or []
            base["hosts"] = len(got.get("hosts") or [])
            base["vms"] = len(vms)
            for v in vms:
                state = str(v.get("state") or "").lower()
                if state.startswith("run") or state in ("on", "poweredon"):
                    base["on"] += 1
                else:
                    base["off"] += 1
        except Exception as e:                                # noqa: BLE001
            base["error"] = str(e)[:120]
        return base
    got = [g for g in fleet._pmap(one, conns, workers=min(4, len(conns))) if g]
    return {"conns": len(conns), "sites": got,
            "vms": sum(g["vms"] for g in got),
            "on": sum(g["on"] for g in got)}


def _dbs_roll() -> dict:
    """Registered database servers, grouped by engine.

    Deliberately makes no connection. Every other panel here reads something
    live, but a database server is registered by host and port with no stored
    credentials — there is nothing to authenticate with, and probing every
    server on every page load would be a port scan on a timer. The recorded
    result of the last explicit test is shown instead, with its age.
    """
    rows = store.all_db()
    engines: dict[str, dict] = {}
    for c in rows:
        kind = c.get("type", "?")
        meta = dbconn.PROVIDERS.get(kind, {})
        e = engines.setdefault(kind, {
            # `key` so the panel can ask for the engine's mark; `icon` stays
            # for the places that still need a plain character.
            "key": kind,
            "label": meta.get("label", kind), "icon": meta.get("icon", ""),
            "count": 0, "ok": 0, "failed": 0, "untested": 0, "servers": []})
        e["count"] += 1
        status = str(c.get("status") or "")
        if status.startswith("ok:"):
            e["ok"] += 1
        elif status.startswith("failed:"):
            e["failed"] += 1
        else:
            e["untested"] += 1
        e["servers"].append({"name": c.get("name", "?"),
                            "where": dbconn.label(c),
                            "state": ("ok" if status.startswith("ok:")
                                      else "failed" if status.startswith("failed:")
                                      else "untested"),
                            "detail": status.split(":", 1)[-1].strip()[:90]})
    return {"conns": len(rows),
            "engines": [engines[k] for k in sorted(engines)],
            "failed": sum(e["failed"] for e in engines.values())}


def _logs_roll() -> dict:
    """Error volume per log store, honouring the same cooldown as the Logs page
    so an unreachable store costs nothing here either."""
    conns = store.all_log()
    if not conns:
        return {"conns": 0, "stores": []}
    def one(c):
        message, left = logstore.cooling(c)
        if message:
            return {"name": c.get("name", "?"), "error": message, "left": left}
        try:
            o = logstore.overview(c)
            return {"name": c.get("name", "?"), "errors": o.get("recent_errors"),
                    "streams": o.get("streams"), "unit": o.get("unit", "stream"),
                    "docs": o.get("docs"), "error": ""}
        except Exception as e:                                # noqa: BLE001
            return {"name": c.get("name", "?"), "error": str(e)[:120], "left": 0}
    got = [g for g in fleet._pmap(one, conns, workers=min(4, len(conns))) if g]
    return {"conns": len(conns), "stores": got}


# ── search ─────────────────────────────────────────────────────


@app.get("/overview/panel/{pid}", response_class=HTMLResponse)
def overview_panel(request: Request, pid: str, refresh: str = ""):
    """One panel's body, so a panel with its own interval can refresh alone.

    It builds only that panel's declared needs, which is the whole reason a
    per-panel interval is worth having: a 15-second alerts panel costs the alerts
    roll every 15 seconds and nothing else.
    """
    if pid not in layout.CATALOGUE:
        raise HTTPException(404)
    if refresh:
        # A panel asking for itself is asking for current data. Unlike the page's
        # Refresh this does not mark the whole fleet stale — only the panel's own
        # sources are rebuilt by the readers below.
        summary.invalidate()
    want = set(layout.CATALOGUE[pid]["needs"])
    data = _board_data(want)
    f = data.get("fleet")
    return templates.TemplateResponse(
        request, f"panels/{pid}.html",
        # `f` and `t` are the shorthands home.html sets for its panels. A panel
        # rendered on its own has no page around it to set them, and four of the
        # twelve raise UndefinedError without them.
        ctx(request, d=data, fleet=f, f=f, t=(f or {}).get("totals"),
            trend=data.get("trend"), agg=data.get("agg"),
            pipes=data.get("pipes"), sec=data.get("sec")))


@app.get("/search", response_class=HTMLResponse)
def search_page(request: Request, q: str = ""):
    return templates.TemplateResponse(
        request, "search.html",
        {"request": request, "status": None, "results": search.search(q), "q": q})


# ── compare ────────────────────────────────────────────────────
@app.get("/compare", response_class=HTMLResponse)
def compare_page(request: Request, mode: str = "sweep", pid: str = "",
                 rgid: str = "", service: str = "", envs: str = "",
                 a: str = "", b: str = "", rga: str = "", ea: str = "",
                 rgb: str = "", eb: str = "", only: str = ""):
    """One page. A sweep with a single service ticked IS the one-service
    comparison, so the mode toggle went — there is nothing the pair form could
    ask that this cannot.

    The a/b tokens still arrive, from the "Compare with…" button on a service
    page and from anybody's bookmark, so they are translated into a sweep
    selection rather than refused: the project and that side's region and
    environment are filled in, and the service itself is ticked.
    """
    picked_svc = list(request.query_params.getlist("svc"))
    for token, (rg_key, env_key) in ((a, ("rga", "ea")), (b, ("rgb", "eb"))):
        parts = compare.decode(token)
        if not parts:
            continue
        tpid, trg, tenv, tfile = parts
        pid = pid or tpid
        if rg_key == "rga":
            rga, ea = rga or trg, ea or tenv
        else:
            rgb, eb = rgb or trg, eb or tenv
        name = repo.display(tpid, tfile)
        if name and name not in picked_svc:
            picked_svc.append(name)
    # `matrix` is still honoured for a bookmark that asks for it; nothing in the
    # page produces one any more.
    if mode not in ("sweep", "matrix"):
        mode = "sweep"
    result = None
    # A mode that cannot run says why. The first version returned the bare form
    # when a field was missing, so a submitted sweep with no project looked
    # exactly like a page nobody had submitted — which is how a missing hidden
    # field went unnoticed.
    why = ""
    if mode == "sweep" and not (pid and rga and ea and rgb and eb):
        if any((pid, rga, ea, rgb, eb)):
            missing = [name for name, v in (("project", pid), ("A's region", rga),
                                            ("A's environment", ea),
                                            ("B's region", rgb),
                                            ("B's environment", eb)) if not v]
            why = ("Nothing to compare — this needs "
                   + ", ".join(missing) + ".")
    if mode == "sweep" and pid and rga and ea and rgb and eb:
        # An explicit service list narrows it; empty means every service either
        # side has, which is the reason this mode exists.
        want = [s for s in picked_svc if s]
        result = compare.sweep(pid, rga, ea, rgb, eb, want or None)
        if only:
            # "differing only" is a view of the same result, not a second sweep:
            # the totals still describe everything that was compared.
            result = {**result, "services": [
                r for r in result["services"]
                if r["only"] or r["error"] or r["counts"]["diff"]
                or r["counts"]["secret_diff"] or r["counts"]["meta_diff"]]}
    elif mode == "matrix" and pid and rgid and service:
        chosen = [e for e in envs.split(",") if e] or None
        files, available = {}, []
        # `ename`, not `env`: the module of that name is imported at the top of
        # this file, and a loop variable shadows it for the rest of the
        # function. Nothing here needs it today, which is precisely how this
        # kind of thing survives to the edit that does — the same shadowing
        # caught two templates in this codebase already.
        for ename, flist in repo.list_envs(pid, rgid, include_hidden=True).items():
            match = next((f for f in flist
                          if repo.display(pid, f) == service), None)
            if match:
                available.append(ename)
                files[ename] = match
        use = [e for e in (chosen or available) if e in files]
        if len(use) >= 2:
            result = compare.matrix(pid, rgid, service, use, files)
        if result:
            result["available_envs"] = available
    return templates.TemplateResponse(
        request, "compare.html",
        {"request": request, "status": None, "tree": compare.tree(),
         "mode": mode, "sel": {"pid": pid, "rgid": rgid, "service": service,
                               "envs": envs, "a": a, "b": b,
                               "rga": rga, "ea": ea, "rgb": rgb, "eb": eb,
                               "svc": picked_svc,
                               "only": only},
         "why": why, "result": result})


# ── clusters & repos overview ──────────────────────────────────
@app.get("/clusters", response_class=HTMLResponse)
def clusters_page(request: Request, project: str = "", cluster: str = "",
                  tab: str = "overview", ns: str = "", q: str = "",
                  refresh: str = "", msg: str = "", err: str = "",
                  inspect: str = "", target: str = "", wns: str = "",
                  wkind: str = "", env: str = "", job: str = "",
                  sec: str = "", from_tab: str = "", node: str = "",
                  workload: str = "", sev: str = ""):
    return _clusters_render(request, project, cluster, tab, ns, q, refresh,
                            msg, err, inspect=inspect, target=target,
                            wns=wns, wkind=wkind, env=env, job=job, sec=sec,
                            from_tab=from_tab, node=node, workload=workload,
                            sev=sev)


def _clusters_render(request: Request, project: str = "", cluster: str = "",
                     tab: str = "overview", ns: str = "", q: str = "",
                     refresh: str = "", msg: str = "", err: str = "",
                     shell: dict | None = None, cmd: str = "",
                     inspect: str = "", target: str = "",
                     wns: str = "", wkind: str = "",
                     created: dict | None = None, env: str = "",
                     job: str = "", shell_out: dict | None = None,
                     sec: str = "", from_tab: str = "", node: str = "",
                     workload: str = "", sev: str = ""):
    """Three levels, the same shape as Pipelines, Security and Logs:
         /clusters                          → a box per project
         ?project=<pid>                     → a box per environment
         ?project=<pid>&cluster=<cid>       → the cluster itself, in depth

    The health figures on the first two levels come from the fleet snapshot,
    which is already cached and shared with the Overview page. Only the third
    level talks to a cluster directly, and only for the tab being shown.
    """
    if refresh:
        fleet.invalidate()
        clusterview.invalidate()
    # The first two levels ARE the snapshot and have to wait for one. The third
    # reads the cluster itself and uses the snapshot for a single health badge,
    # so on a portal that has just started it takes what exists and lets the
    # collection catch up — three seconds of waiting for a badge is three
    # seconds of a page that looks broken.
    if cluster and not refresh:
        snap = fleet.peek() or {"clusters": [], "stale": True}
    else:
        snap = fleet.overview(force=bool(refresh))
    health = {c["cid"]: c for c in snap["clusters"]}
    projects = store.projects()

    if project and project not in projects:
        project = ""
    proj = projects.get(project) or {}
    sel = None
    if project and cluster:
        got = store.get_cluster(project, cluster)
        if got:
            sel = {**got, "id": cluster}

    stage = "cluster" if sel else ("project" if project else "hub")
    data = tabs = None
    nslist, pending = [], []
    if sel:
        known = dict((t[0], t) for t in clusterview.TABS)
        tab = tab if tab in known else "overview"
        # Where the kubectl console goes when it is closed. It is a whole page
        # rather than a window over one, so closing it has to navigate — and it
        # navigated to Overview, throwing away both the tab it was opened from
        # and the namespace that had been chosen. Validated against the tab list
        # because it arrives in a query string and ends up in a URL.
        from_tab = from_tab if from_tab in known and from_tab != "shell" else ""
        tabs = clusterview.TABS
        warmer.note_view("cluster", cluster)
        # Measured cold against a real cluster: the tab's own reads, then the
        # namespace list, then the nodes — 1.6s + 2.5s + 3.8s, one after
        # another, because each was a separate blocking call. Eight and a half
        # seconds for a page whose slowest single read is under four. They go
        # together now, and whatever has not arrived within FIRST_PAINT is
        # named rather than waited for.
        #
        # The machines belong above every tab, not only the two that used to
        # ask for them: a pod that will not schedule and a volume that will not
        # bind both read differently once you can see a node is gone.
        want = list(dict.fromkeys(
            clusterview.NEEDS.get(tab, ()) + ("namespaces", "nodes")
            + (("netshoots",) if kmanage.writable(sel) else ())))
        got = clusterview.gathered(sel, want, refresh=bool(refresh))
        data, pending = got["parts"], got["pending"]
        if tab == "overview" and not pending:
            data["summary"] = clusterview._summarise(data)
        nslist = (data.get("namespaces") or {}).get("namespaces") or []
        if got["errors"]:
            err = err or f"could not read the cluster: {got['errors'][0][:200]}"

    # one pod, opened for a closer look: its description or the tail of its log.
    # Rendered above the table so the list stays where it was.
    look = None
    if sel and tab == "pods" and inspect == "shell" and "/" in target:
        pod_ns, _, pod_name = target.partition("/")
        look = {"kind": "shell", "target": target, "namespace": pod_ns,
                "pod": pod_name, "out": shell_out,
                "netshoot": pod_name.startswith("netshoot-")}
    elif sel and tab == "pods" and inspect and "/" in target:
        pod_ns, _, pod_name = target.partition("/")
        if inspect == "logs":
            look = {"kind": "logs", "target": target,
                    **clusterview.pod_logs(sel, pod_ns, pod_name)}
        else:
            look = {"kind": "describe", "target": target,
                    **clusterview.describe(sel, "pod", pod_name, pod_ns)}

    access_view = None
    if sel and tab == "access":
        access_view = access.listing(sel)

    # the security audit: read-only, nothing installed in the cluster
    scan_view = None
    if sel and tab == "scan":
        scan_view = {"audit": clusterview.part(sel, "audit",
                                               refresh=bool(refresh))}

    cards = []
    # flat every-cluster list + estate tallies, for the hub's All / Attention tabs
    clist, ctot = [], {"clusters": 0, "nodes": 0, "ready": 0, "bad": 0,
                       "down": 0, "attention": 0}
    if stage == "hub":
        for pid2, p2 in projects.items():
            mine = [health.get(cid2, {"cid": cid2, "name": c2.get("name", cid2),
                                      "reachable": False,
                                      "error": "not collected"})
                    for cid2, c2 in (p2.get("clusters") or {}).items()]
            envs = sum(len(rg.get("env_clusters") or {})
                       for rg in (p2.get("regions") or {}).values())
            cards.append({
                "pid": pid2, "project": p2, "clusters": mine, "envs": envs,
                "regions": len(p2.get("regions") or {}),
                "nodes": sum((c2.get("nodes") or {}).get("total", 0) for c2 in mine),
                "ready": sum((c2.get("nodes") or {}).get("ready", 0) for c2 in mine),
                "pods": sum((c2.get("pods") or {}).get("total", 0) for c2 in mine),
                "bad": sum((c2.get("pods") or {}).get("bad", 0) for c2 in mine),
                "down": sum(1 for c2 in mine if not c2.get("reachable")),
                "href": f"/clusters?project={pid2}",
            })
        for pid2, p2 in projects.items():
            pname = p2.get("name", pid2)
            mapped = {cid3: [r["where"] for r in rows]
                      for cid3, rows in store.serves(projects, pid2).items()}
            for cid2, c2 in (p2.get("clusters") or {}).items():
                h = health.get(cid2, {"reachable": False, "error": "not collected"})
                bad = (h.get("pods") or {}).get("bad", 0)
                att = (not h.get("reachable")) or bool(bad)
                clist.append({
                    "cid": cid2, "name": c2.get("name", cid2), "pid": pid2,
                    "project": pname, "where": ", ".join(mapped.get(cid2, [])) or "unmapped",
                    "health": h, "prod": _cluster_is_prod(pid2, cid2), "attention": att,
                    "href": f"/clusters?project={pid2}&cluster={cid2}"})
                ctot["clusters"] += 1
                ctot["nodes"] += (h.get("nodes") or {}).get("total", 0)
                ctot["ready"] += (h.get("nodes") or {}).get("ready", 0)
                ctot["bad"] += bad
                ctot["down"] += 0 if h.get("reachable") else 1
                ctot["attention"] += 1 if att else 0
        # what needs a look first: attention on top, then by project + name
        clist.sort(key=lambda x: (not x["attention"], x["project"].lower(), x["name"].lower()))
    elif stage == "project":
        # one box per environment that has a cluster, then any cluster no
        # environment points at — an unmapped cluster is easy to forget, so it is
        # shown rather than hidden
        claimed = set()
        for rgid, rg in (proj.get("regions") or {}).items():
            for env_name, cid2 in (rg.get("env_clusters") or {}).items():
                c2 = store.get_cluster(project, cid2)
                if not c2:
                    continue
                claimed.add(cid2)
                cards.append({
                    "kind": "env", "region": rg, "env": env_name, "cid": cid2,
                    "cluster": c2, "health": health.get(cid2, {}),
                    "config_url": f"/p/{project}/{rgid}/{env_name}",
                    "href": f"/clusters?project={project}&cluster={cid2}",
                })
        for cid2, c2 in (proj.get("clusters") or {}).items():
            if cid2 in claimed:
                continue
            cards.append({
                "kind": "cluster", "region": None, "env": "", "cid": cid2,
                "cluster": c2, "health": health.get(cid2, {}), "config_url": "",
                "href": f"/clusters?project={project}&cluster={cid2}",
            })

    used_by = []
    if sel:
        used_by = store.serves({project: proj}, project).get(cluster, [])

    # the topology drawing for the environment this cluster serves. One cluster
    # can serve several, so `env` picks; without it, the first one.
    topo = svg = None
    diagram_env = None
    if sel and tab == "diagram" and used_by:
        pick = next((u for u in used_by if u["env"] == env), used_by[0])
        diagram_env = pick
        ns_list = repo.namespaces(project, pick["rgid"], pick["env"])
        if not ns_list:
            topo = {"error": "no namespaces found in this environment's values "
                             "files, so there is nothing to draw"}
        else:
            topo = topology.collect(project, pick["rgid"], pick["env"], sel,
                                    ns_list)
            if not topo.get("error"):
                # The page's own URL, so a box in the drawing can link to the tab
                # that holds its detail. Without it render() draws the same
                # picture inert, which is what a page with no cluster wants.
                svg = diagram.render(
                    topo, base=f"/clusters?project={project}&cluster={cluster}")

    # ── the values files for whatever this cluster runs ──────────
    # Deliberately from the git working copy, not from the cluster: the repo is
    # the source of truth, and this is where an edit has to start if ArgoCD is
    # going to keep it. One block per environment the cluster serves.
    config_envs = []
    if sel and tab == "config":
        for u in used_by:
            rgid, env = u["rgid"], u["env"]
            groups = repo.split_services(project, rgid, env)
            files = groups["all"]
            st = git_ops.region_status(project, rgid, env=env)
            dirty = git_ops.dirty_paths(project, rgid, env=env)
            services = []
            for fname in files:
                rel = repo.rel_path(project, rgid, env, fname)
                summary = repo.service_summary(project, rgid, env, fname)
                services.append({
                    "fname": fname, "name": repo.display(project, fname),
                    "focus": fname in groups["focus"],
                    "ambiguous": repo.display(project, fname) in groups["ambiguous"],
                    # not "keys": on a dict, Jinja resolves that to dict.keys
                    "key_count": summary.get("cfg_count", 0),
                    "secrets": summary.get("secret_count", 0),
                    "warnings": summary.get("warnings") or [],
                    "error": summary.get("error", ""),
                    "modified": rel in dirty,
                    "url": f"/p/{project}/{rgid}/{env}/s/{fname}",
                })
            b = repo.binding(project, rgid, env)
            config_envs.append({
                "label": u["label"], "rgid": rgid, "env": env,
                "url": u["url"], "branch": st.get("branch", ""),
                "head": st.get("head", ""), "stale": st.get("stale"),
                "pending": len(dirty), "services": services,
                # where these files actually come from. With one repository per
                # region this was the same answer for every environment and not
                # worth showing; now it is the first thing to check when an
                # environment shows values somebody does not recognise.
                "repo_url": gitrepo.web_url(b["url"]) or b["url"],
                "path": b["path"],
                "is_prod": config.is_prod_env(env, repo.naming(project)["aliases"]),
            })

    # Workloads: the rows for the namespace in view, and the strip of kinds over
    # them. Both are built here because the sub-tab counts have to be of the rows
    # the table is about to show — and because a `wkind` naming a kind that is
    # not in view must select nothing rather than an empty table under a tab that
    # claims to have rows.
    wrows, wtabs = [], []
    if data and tab == "workloads":
        wrows = [r for r in (data.get("workloads") or {}).get("workloads") or []
                 if not ns or r.get("namespace") == ns]
        wtabs = clusterview.kind_tabs(wrows)
        wkind = wkind if any(t["key"] == wkind for t in wtabs) else ""
        if wkind:
            wrows = [r for r in wrows if r.get("kind") == wkind]

    # pid goes through ctx() so the per-project naming helpers (env_label,
    # env_glyph) pick up this project's aliases from the render context
    return templates.TemplateResponse(
        request, "clusters.html",
        ctx(request, pid=project, stage=stage, cards=cards, clist=clist, ctot=ctot,
            projects=projects,
            proj=proj, sel=sel, cid=cluster, tab=tab,
            tabs=tabs, data=data, health=health.get(cluster, {}),
            nodestrip=(clusterview.node_strip(data.get("nodes") or {})
                       if sel and data else None),
            nslist=nslist, collecting=pending,
            used_by=used_by, config_envs=config_envs, ns=ns, q=q,
            snap=snap, msg=msg, err=err, look=look, inspect=inspect,
            target=target, wns=wns, wkind=wkind, sec=sec, from_tab=from_tab,
            node=node, workload=workload,
            # validated against the audit's own list, because it reaches a URL
            sev=sev if sev in audit.SEVERITIES else "",
            wrows=wrows, wtabs=wtabs,
            access_view=access_view, created=created, scan=scan_view,
            severities_scan=audit.SEVERITIES,
            topo=topo, svg=svg, diagram_env=diagram_env,
            presets=access.PRESETS, verbs=access.VERBS,
            writable=kmanage.writable(sel) if sel else False,
            is_prod=_cluster_is_prod(project, cluster),
            all_clusters=_cluster_choices(), shell=shell, cmd=cmd,
            # `data` is None at the first two levels — there is no cluster to
            # have read anything from.
            netshoots=(((data or {}).get("netshoots") or {})
                       .get("netshoots") or []),
            actions=kmanage.ACTIONS))


@app.post("/clusters/shell", response_class=HTMLResponse)
async def cluster_shell(request: Request):
    """Run one typed kubectl command against one cluster.

    Rendered rather than redirected: the output is the answer, and it is too
    large for a query string. Every attempt is audited, including refusals —
    what someone tried to run is as interesting as what ran.
    """
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    raw = str(f.get("cmd", ""))
    confirm = str(f.get("confirm", "")).strip()
    me = getattr(request.state, "user", None)
    sel = store.get_cluster(project, cid)
    if not sel:
        return RedirectResponse("/clusters?err=unknown cluster", 303)
    sel = {**sel, "id": cid}
    ip = _client_ip(request)
    result, err = None, ""
    try:
        kind = kmanage.classify(kmanage.parse(raw))
        if kind == "write" and (why := aitools.confirm_prod(
                project, cid, sel, confirm,
                "in the confirmation box to run a command that changes it")):
            raise kmanage.Refused(why)
        result = await run_in_threadpool(
            kmanage.run, sel, raw, allow_write=kmanage.writable(sel))
        auth.audit(me, f"kubectl_{result['kind']}", sel.get("name", cid),
                   f"exit {result['code']} · {result['display'][:300]}", ip)
    except kmanage.Refused as e:
        err = str(e)
        auth.audit(me, "kubectl_refused", sel.get("name", cid),
                   f"{err[:150]} · {raw[:200]}", ip)
    if result and result["kind"] == "write":
        clusterview.invalidate()      # the cluster just changed; drop the cache
        fleet.invalidate()
    return _clusters_render(request, project, cid, "shell", err=err,
                            shell=result, cmd=raw)


def _cluster_for(request: Request, project: str, cid: str):
    """The stored cluster, if this person may manage it. (cluster, error)."""
    me = _may(request, "manage")
    if not me:
        return None, None, "you do not have cluster management"
    sel = store.get_cluster(project, cid)
    if not sel:
        return me, None, "no such cluster"
    sel = {**sel, "id": cid}
    if not kmanage.writable(sel):
        return me, sel, kmanage.read_only_why()
    return me, sel, ""


@app.post("/clusters/exec")
async def cluster_exec(request: Request):
    """One command inside one container. Not a session — see kmanage.exec_in."""
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    ns, pod = str(f.get("namespace", "")), str(f.get("pod", ""))
    cmd, container = str(f.get("cmd", "")), str(f.get("container", ""))
    back = _return_to(f, f"/clusters?project={project}&cluster={cid}&tab=pods")
    me, sel, why = _cluster_for(request, project, cid)
    if why:
        return RedirectResponse(_with(back.split("?")[0],
                                      back.partition("?")[2], err=why), 303)
    try:
        got = await run_in_threadpool(kmanage.exec_in, sel, ns, pod, cmd,
                                      container, True)
    except kmanage.Refused as e:
        return RedirectResponse(_with(back.split("?")[0],
                                      back.partition("?")[2], err=str(e)), 303)
    # The whole command is recorded. That is the difference between this and
    # the interactive shell the console still refuses: afterwards, anybody can
    # say exactly what was run inside which container.
    auth.audit(me, "pod_exec", f"{sel.get('name')} · {ns}/{pod}",
               f"{got['display']} → exit {got['code']}", _client_ip(request))
    return _clusters_render(request, project, cid, "pods",
                            ns=str(f.get("ns", "")), q=str(f.get("q", "")),
                            inspect="shell", target=f"{ns}/{pod}",
                            shell_out=got, cmd=cmd)


@app.post("/clusters/exec.json")
async def cluster_exec_json(request: Request):
    """The same command, answered as JSON so the terminal can append.

    A full page render per command turns a terminal into a form: you lose the
    scrollback, the cursor and your place on the page. This returns only the
    result and the window keeps its own history.
    """
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    ns, pod = str(f.get("namespace", "")), str(f.get("pod", ""))
    cmd, container = str(f.get("cmd", "")), str(f.get("container", ""))
    me, sel, why = _cluster_for(request, project, cid)
    if why:
        return JSONResponse({"ok": False, "code": 126, "stdout": "",
                             "stderr": why, "took": 0, "display": cmd}, 200)
    try:
        got = await run_in_threadpool(kmanage.exec_in, sel, ns, pod, cmd,
                                      container, True)
    except kmanage.Refused as e:
        return JSONResponse({"ok": False, "code": 126, "stdout": "",
                             "stderr": str(e), "took": 0, "display": cmd}, 200)
    auth.audit(me, "pod_exec", f"{sel.get('name')} · {ns}/{pod}",
               f"{got['display']} → exit {got['code']}", _client_ip(request))
    return JSONResponse(got, 200)


def _ws_user(ws: WebSocket):
    """The signed-in person behind a socket, or None.

    The login middleware is `@app.middleware("http")` and a WebSocket is not
    http, so none of it has run. `current_user` is reused rather than repeated —
    it reads `.session`, which a socket has too — and the area check that the
    middleware would have made is made here. Writing the checks out a second
    time is how one of them ends up missing, and the missing one would make the
    terminal the way in.
    """
    u = current_user(ws)
    return u if u and rbac.may_area(u, "manage") else None


def _ws_ansible(ws: WebSocket):
    """The signed-in person behind a socket if they may run playbooks.

    Same reasoning as _ws_user: the http login middleware never ran for a
    socket, so the area check is made here. Opening a shell on a host is at
    least what running a playbook against it is, so it takes the same area.
    """
    u = current_user(ws)
    return u if u and rbac.may_area(u, "ansible_run") else None


@app.websocket("/clusters/pty.ws")
async def cluster_pty(ws: WebSocket, project: str = "", cluster: str = "",
                      namespace: str = "", pod: str = "", container: str = "",
                      rows: int = 24, cols: int = 100):
    """A terminal in a container: keystrokes down, whatever it prints back.

    Not a command runner. `nslookup` takes the keyboard and answers at its own
    prompt, `top` repaints the screen, a password prompt turns echo off — none
    of which can be expressed as "run this, here is the output". So nothing on
    this side interprets anything; the shell in the container does the echoing,
    the editing, the history and the completion, and the browser draws what
    arrives.

    Text frames in are JSON: {"i": "keystrokes"} or {"r": [rows, cols]}.
    Text frames out are the container's own bytes, decoded as they arrive.
    """
    await ws.accept()
    me = _ws_user(ws)
    sel = (store.get_project(project) or {}).get("clusters", {}).get(cluster)
    why = ("" if me else "you do not have cluster management") or \
          ("" if sel else "no such cluster")
    if not why and not kmanage.writable({**sel, "id": cluster}):
        why = kmanage.read_only_why()
    # 4001 means "this never became a terminal". The browser closes the window
    # by itself when a shell ENDS — somebody typed exit — and for a while it did
    # that on any close at all, so an environment where the shell could not
    # start showed its reason for a fraction of a second and then navigated
    # away. The close code is what tells the two apart; the reason rides with
    # it, because a message the reader cannot get back to is not a message.
    async def refuse(text: str) -> None:
        await ws.send_text(f"\r\n\x1b[31m{text}\x1b[0m\r\n")
        # a close reason is capped at 123 bytes by the protocol
        await ws.close(code=4001, reason=text[:110])

    if why:
        await refuse(why)
        return
    sel = {**sel, "id": cluster}
    where = f"{sel.get('name')} · {namespace}/{pod}"
    ip = _client_ip(ws)
    try:
        term = await run_in_threadpool(kmanage.pty_open, sel, namespace, pod,
                                       container, rows, cols, True)
    except kmanage.Refused as e:
        await refuse(str(e))
        return
    auth.audit(me, "pod_shell", where, "interactive terminal opened", ip)
    typed = kmanage.pty_audit_line()
    # Bytes can be cut anywhere, including through the middle of a character.
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def record(lines):
        for line in lines:
            auth.audit(me, "pod_shell", where, line, ip)

    async def to_browser():
        while True:
            try:
                data = await run_in_threadpool(term.read, 0.2)
            except EOFError:
                return
            if data:
                text = decoder.decode(data)
                typed.saw_output(text)
                await ws.send_text(text)
            # This loop is also the clock the audit runs on: a line held back
            # waiting to see whether the container echoes it is settled here.
            record(typed.due())

    async def to_pod():
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if "r" in msg:
                await run_in_threadpool(term.resize, int(msg["r"][0]),
                                        int(msg["r"][1]))
                continue
            keys = str(msg.get("i", ""))
            if not keys:
                continue
            used.add(1)
            # Recorded as each line settles rather than at the end, so a
            # session that is still open is already in the log.
            record(typed.typed(keys))
            await run_in_threadpool(term.write, keys.encode("utf-8"))

    used: set = set()          # whether a key was ever pressed — see below
    try:
        async with anyio.create_task_group() as tg:
            async def wrap(job):
                await job()
                tg.cancel_scope.cancel()      # either end closing ends both
            tg.start_soon(wrap, to_browser)
            tg.start_soon(wrap, to_pod)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        # kubectl exits non-zero and the shell was never used: this did not end,
        # it failed. Whatever kubectl printed is already on the screen, but it
        # is a sentence about RBAC groups — so the cluster is asked what the
        # actual obstacle is and told plainly. Only on this path: `auth can-i`
        # is a round trip and a working terminal must not pay for it.
        code = term.proc.poll()
        failed = not used and code not in (0, None)
        with anyio.CancelScope(shield=True):
            if failed:
                with contextlib.suppress(Exception):
                    said = await run_in_threadpool(
                        kmanage.why_refused, sel, namespace, "exec")
                    if said:
                        await ws.send_text(f"\r\n\x1b[33m{said}\x1b[0m\r\n")
            await run_in_threadpool(term.close)
        record(typed.close())        # anything still waiting on its echo
        auth.audit(me, "pod_shell", where,
                   (f"terminal failed to start (kubectl exit {code})" if failed
                    else f"terminal closed after "
                         f"{round(time.time() - term.opened)}s"), ip)
        with contextlib.suppress(RuntimeError):
            # 4001 again: the browser keeps the window open for it, so the
            # reason above can be read instead of flashing past.
            await ws.close(code=4001) if failed else await ws.close()


@app.websocket("/ansible/host.ws")
async def ansible_host_terminal(ws: WebSocket, gid: str = "", host: str = "",
                                rows: int = 24, cols: int = 100):
    """A terminal on one inventory host, authenticated by the group's key.

    The same shape as the pod terminal, onto a VM instead of a container: JSON
    keystrokes down, the host's own bytes back, nothing on this side
    interpreting anything. The group's stored key is written to a 0600 file for
    the life of the session and removed when it ends.
    """
    await ws.accept()
    me = _ws_ansible(ws)
    g = ansible.group(gid)

    async def refuse(text: str) -> None:
        await ws.send_text(f"\r\n\x1b[31m{text}\x1b[0m\r\n")
        await ws.close(code=4001, reason=text[:110])

    if not me:
        await refuse("you do not have Ansible: run playbooks")
        return
    if not g:
        await refuse("that group is gone")
        return
    if g.get("is_prod") and ws.query_params.get("confirm", "") != g["name"]:
        await refuse(f"{g['name']} is marked production — type its name to open "
                     f"a terminal on it")
        return
    ip = _client_ip(ws)
    where = f"{g['name']} \u00b7 {host}"
    try:
        term = await run_in_threadpool(ansible.host_shell, g, host, rows, cols)
    except ansible.Refused as e:
        await refuse(str(e))
        return
    auth.audit(me, "ansible_host_shell", where, "terminal opened", ip)
    typed = kmanage.pty_audit_line()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    used: set = set()
    # A recording of this session, in the unified Privileged Access store — a
    # host terminal opened from Ansible is a recorded SSH session like any other,
    # it just carries source='ansible'. None when recording is off; output() /
    # commands_typed() no-op on None so the loop does not branch on it.
    # The recording is tagged with the HOST's id (the derived PAM target's id),
    # not the group's, so per-device RBAC lines up: a person granted this host
    # sees this session. A group has many hosts; scoping by the group id would
    # leak every host's recordings to anyone granted any one of them.
    hrec = next((h for h in g.get("hosts", []) if h.get("name") == host), None)
    rec = pam.start_recording(
        me.get("email", "anonymous"), ip, protocol="ssh",
        target_id=(hrec or {}).get("id", ""),
        target_name=host, address=host, pid=g.get("pid", ""),
        rgid=g.get("rgid", ""), source="ansible", rec_kind="asciinema",
        rows=rows, cols=cols)

    def record(lines):
        for line in lines:
            auth.audit(me, "ansible_host_shell", where, line, ip)
        if rec:
            rec.commands_typed(lines)

    async def to_browser():
        while True:
            try:
                data = await run_in_threadpool(term.read, 0.2)
            except EOFError:
                return
            if data:
                text = decoder.decode(data)
                typed.saw_output(text)
                if rec:
                    rec.output(text)
                await ws.send_text(text)
            record(typed.due())

    async def to_host():
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if "r" in msg:
                r, c = int(msg["r"][0]), int(msg["r"][1])
                await run_in_threadpool(term.resize, r, c)
                if rec:
                    rec.resize(r, c)
                continue
            keys = str(msg.get("i", ""))
            if not keys:
                continue
            used.add(1)
            record(typed.typed(keys))
            await run_in_threadpool(term.write, keys.encode("utf-8"))

    try:
        async with anyio.create_task_group() as tg:
            async def wrap(job):
                await job()
                tg.cancel_scope.cancel()
            tg.start_soon(wrap, to_browser)
            tg.start_soon(wrap, to_host)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        code = term.proc.poll()
        failed = not used and code not in (0, None)
        with anyio.CancelScope(shield=True):
            await run_in_threadpool(term.close)
            ansible.drop_session_dir(getattr(term, "workdir", ""))
        record(typed.close())
        if rec:
            await run_in_threadpool(rec.finish,
                                    "failed" if failed else "closed")
        auth.audit(me, "ansible_host_shell", where,
                   (f"terminal failed to start (ssh exit {code})" if failed
                    else f"terminal closed after "
                         f"{round(time.time() - term.opened)}s"), ip)
        with contextlib.suppress(RuntimeError):
            await ws.close(code=4001) if failed else await ws.close()


def _cluster_read(request: Request, project: str, cid: str):
    """The stored cluster, for somebody who may READ clusters. (cluster, error).

    Separate from _cluster_for, which also demands management and a writable
    cluster. Reading a pod's log changes nothing, and gating it behind
    management would mean an on-call engineer with read access cannot see why a
    pod is crash-looping — which is the whole reason they were paged.
    """
    me = _may(request, "clusters")
    if not me:
        return None, "you do not have cluster access"
    sel = store.get_cluster(project, cid)
    if not sel:
        return None, "no such cluster"
    return {**sel, "id": cid}, ""


@app.get("/clusters/containers.json")
def cluster_pod_containers(request: Request, project: str = "",
                           cluster: str = "", namespace: str = "",
                           pod: str = ""):
    """Which containers a pod has, so the log window can offer the picker."""
    sel, why = _cluster_read(request, project, cluster)
    if why:
        return JSONResponse({"containers": [], "error": why}, 200)
    return JSONResponse({"containers": logs.containers_of(sel, namespace, pod)})


@app.get("/clusters/describe.json")
def cluster_describe_json(request: Request, project: str = "", cluster: str = "",
                          kind: str = "pod", namespace: str = "", name: str = ""):
    """`kubectl describe` for one object, so the window can open over the page.

    Read-only, so it is gated on the clusters area rather than on management —
    the same reasoning as the log stream beside it: describing a pod changes
    nothing, and somebody paged at 02:00 to find out why it is unhappy should not
    need write access to look.
    """
    sel, why = _cluster_read(request, project, cluster)
    if why:
        return JSONResponse({"error": why, "text": ""}, 200)
    got = clusterview.describe(sel, kind or "pod", name, namespace)
    return JSONResponse({"error": got.get("error", ""), "text": got.get("text", ""),
                         "title": f"{kind or 'pod'}/{name}",
                         "namespace": namespace}, 200)


@app.get("/clusters/yaml.json")
def cluster_yaml_read(request: Request, project: str = "", cluster: str = "",
                      kind: str = "pod", namespace: str = "", name: str = ""):
    """One object's YAML, for the editor to open.

    Reading is gated on the clusters area, like describe beside it. Whether the
    reader may APPLY anything is answered here too, so the window can open
    read-only rather than offering a button that will be refused.
    """
    sel, why = _cluster_read(request, project, cluster)
    if why:
        return JSONResponse({"error": why, "text": ""}, 200)
    try:
        got = kmanage.read_yaml(sel, kind or "pod", name, namespace)
    except kmanage.Refused as e:
        return JSONResponse({"error": str(e), "text": ""}, 200)
    may = bool(_may(request, "manage") and kmanage.writable(sel))
    return JSONResponse({
        "error": got.get("error", ""), "text": got.get("text", ""),
        "kind": kind, "name": name, "namespace": namespace,
        "may_write": may,
        # A production cluster wants its name typed before anything is applied.
        # Named here so the window can ask for it up front rather than showing a
        # refusal after somebody has finished editing.
        "confirm": (sel.get("name", "")
                    if aitools.is_prod(project, cluster) else ""),
        "cluster_name": sel.get("name", ""),
    }, 200)


@app.post("/clusters/yaml/apply")
async def cluster_yaml_apply(request: Request):
    """Apply an edited document — or check it without applying anything.

    `dry` runs it through the API server's whole admission path and changes
    nothing, which is the point: a typo in a manifest should be a message, not an
    outage. A real apply goes through the same three gates as the kubectl
    console — the management area, the cluster's own tick, and a typed cluster
    name on production.
    """
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    kind, ns = str(f.get("kind", "")), str(f.get("namespace", ""))
    name, doc = str(f.get("name", "")), str(f.get("yaml", ""))
    dry = str(f.get("dry", "")) == "1"
    me = getattr(request.state, "user", None)
    if not _may(request, "clusters"):
        return JSONResponse({"ok": False, "error": "you do not have cluster "
                                                   "access"}, 200)
    if not _may(request, "manage"):
        return JSONResponse({"ok": False, "error": "you do not have cluster "
                                                   "management"}, 200)
    sel = store.get_cluster(project, cid)
    if not sel:
        return JSONResponse({"ok": False, "error": "no such cluster"}, 200)
    sel = {**sel, "id": cid}
    if not dry:
        if not kmanage.writable(sel):
            return JSONResponse({"ok": False,
                                 "error": kmanage.read_only_why(
                                     "applying a document changes it")}, 200)
        if (bad := aitools.confirm_prod(project, cid, sel,
                                        str(f.get("confirm", "")))):
            return JSONResponse({"ok": False, "error": bad}, 200)
    try:
        got = await run_in_threadpool(
            lambda: kmanage.apply_yaml(sel, kind, name, ns, doc, dry_run=dry,
                                       allow_write=kmanage.writable(sel)))
    except kmanage.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 200)
    if not dry:
        # Audited by WHAT was applied, never the document: a Secret's data must
        # not reach the audit log.
        auth.audit(me, "yaml_applied", f"{sel.get('name')} · {ns}/{kind}/{name}",
                   f"exit {got['code']} · {len(doc)} bytes", _client_ip(request))
        clusterview.invalidate()
    return JSONResponse({"ok": got["ok"], "dry_run": dry,
                         "output": (got["stdout"] or "").strip(),
                         "error": ("" if got["ok"] else
                                   (got["stderr"] or got["stdout"])[-600:]),
                         "display": got["display"]}, 200)


@app.get("/clusters/logstream")
def cluster_pod_logstream(request: Request, project: str = "",
                          cluster: str = "", namespace: str = "",
                          pod: str = "", container: str = "", tail: int = 200,
                          previous: str = ""):
    """A pod's log, followed, addressed by CLUSTER rather than environment.

    The environment-keyed route below can only reach a pod in a namespace some
    environment maps to, which is why the cluster page's own log view used to
    offer "stream live" only when the pod happened to belong to a mapped
    environment — and sent you to a different page when it did.
    """
    sel, why = _cluster_read(request, project, cluster)
    if why:
        return StreamingResponse(iter([logs.sse("error", why)]),
                                 media_type="text/event-stream")
    return StreamingResponse(
        logs.stream(sel, namespace, pod, container, tail, bool(previous)),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/clusters/netshoot.json")
async def cluster_netshoot_json(request: Request):
    """Start a troubleshooting pod, answering as JSON so the window can narrate.

    The wait is 30s the first time an image is pulled onto a node. Blocking a
    form post for that long tells the reader nothing at all — this reports what
    happened so the terminal can say which step it is on.
    """
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    ns = str(f.get("namespace", "")) or "default"
    me, sel, why = _cluster_for(request, project, cid)
    if why:
        return JSONResponse({"ok": False, "error": why}, 200)
    try:
        got = await run_in_threadpool(kmanage.netshoot_start, sel, ns, True)
    except kmanage.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 200)
    auth.audit(me, "netshoot_start", f"{sel.get('name')} · {ns}/{got['name']}",
               f"{got['image']}, deletes itself after {got['ttl']}s",
               _client_ip(request))
    clusterview.forget(cid, "pods", "netshoots")
    return JSONResponse({"ok": bool(got["ready"]), **got}, 200)


@app.post("/clusters/netshoot")
async def cluster_netshoot(request: Request):
    """Start a throwaway pod with network tools, and open a shell on it."""
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    ns = str(f.get("namespace", "")) or "default"
    back = _return_to(f, f"/clusters?project={project}&cluster={cid}")
    me, sel, why = _cluster_for(request, project, cid)
    if why:
        return RedirectResponse(_with(back.split("?")[0],
                                      back.partition("?")[2], err=why), 303)
    try:
        got = await run_in_threadpool(kmanage.netshoot_start, sel, ns, True)
    except kmanage.Refused as e:
        return RedirectResponse(_with(back.split("?")[0],
                                      back.partition("?")[2], err=str(e)), 303)
    auth.audit(me, "netshoot_start", f"{sel.get('name')} · {ns}/{got['name']}",
               f"{got['image']}, deletes itself after {got['ttl']}s",
               _client_ip(request))
    clusterview.forget(cid, "pods", "netshoots")
    if not got["ready"]:
        return RedirectResponse(
            _with(back.split("?")[0], back.partition("?")[2],
                  err=f"{got['name']} was created but is not ready yet: "
                      f"{got['why']}"), 303)
    # Straight into it, which is the whole point of the button.
    return RedirectResponse(
        f"/clusters?project={project}&cluster={cid}&tab=pods"
        f"&inspect=shell&target={urllib.parse.quote(ns + '/' + got['name'])}"
        f"&msg={urllib.parse.quote('troubleshooting pod ready — it deletes itself in ' + str(got['ttl'] // 60) + ' minutes')}",
        303)


@app.post("/clusters/netshoot/stop")
async def cluster_netshoot_stop(request: Request):
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    ns, name = str(f.get("namespace", "")), str(f.get("name", ""))
    back = _return_to(f, f"/clusters?project={project}&cluster={cid}&tab=pods")
    me, sel, why = _cluster_for(request, project, cid)
    if why:
        return RedirectResponse(_with(back.split("?")[0],
                                      back.partition("?")[2], err=why), 303)
    try:
        got = await run_in_threadpool(kmanage.netshoot_stop, sel, ns, name, True)
    except kmanage.Refused as e:
        return RedirectResponse(_with(back.split("?")[0],
                                      back.partition("?")[2], err=str(e)), 303)
    auth.audit(me, "netshoot_stop", f"{sel.get('name')} · {ns}/{name}",
               got["detail"], _client_ip(request))
    clusterview.forget(cid, "pods", "netshoots")
    return RedirectResponse(_with(back.split("?")[0], back.partition("?")[2],
                                  msg=f"{name} removed"), 303)


@app.post("/clusters/action")
async def cluster_action(request: Request):
    """Run one of the fixed management actions from a tab."""
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    action = str(f.get("action", ""))
    back_to = str(f.get("back", "")) or f"/clusters?project={project}&cluster={cid}"
    if not back_to.startswith("/clusters"):
        back_to = f"/clusters?project={project}&cluster={cid}"
    # The Cluster management area, not merely a signed-in reader. The URL is
    # under /clusters, which the middleware governs with the READ area, and the
    # cluster's own "allow management" tick is a property of the cluster rather
    # than of the person — so without this a role with cluster read access could
    # post a rolling restart, a scale, a rollback or a pod deletion to any
    # cluster with the tick on. rbac.AREAS defines "manage" for exactly this and
    # nothing was asking for it here.
    me = _may(request, "manage")
    if not me:
        return RedirectResponse(
            _with(back_to.split("?")[0], back_to.partition("?")[2],
                  err="your roles do not include Cluster management"), 303)
    sel = store.get_cluster(project, cid)
    if not sel:
        return RedirectResponse("/clusters?err=unknown cluster", 303)
    sel = {**sel, "id": cid}
    args = {k: str(v) for k, v in f.items()
            if k in ("kind", "namespace", "name", "node", "replicas")}
    try:
        # Through aitools, which is also what the assistant rail and MCP call.
        # The production confirmation, the writable check, the audit line and
        # the cache invalidation live there once instead of here, there and in
        # whatever asks next — and a preview a model shows somebody is then the
        # same code path as the thing that runs.
        res = await run_in_threadpool(
            aitools.execute, me, project, cid, action, args,
            str(f.get("confirm", "")), _client_ip(request))
        note = [res["summary"]] if res.get("summary") else []
        flash = f"{res['label']}: {note[0][:160] if note else 'done'}"
        if not res.get("ok"):
            return RedirectResponse(_with(back_to.split("?")[0],
                                          back_to.partition("?")[2],
                                          err=flash), 303)
        return RedirectResponse(_with(back_to.split("?")[0],
                                      back_to.partition("?")[2], msg=flash), 303)
    except (aitools.Denied, kmanage.Refused) as e:
        return RedirectResponse(_with(back_to.split("?")[0],
                                      back_to.partition("?")[2],
                                      err=str(e)), 303)


@app.get("/assistant/agent")
def assistant_agent(request: Request, q: str = ""):
    """Answer by looking as many times as it takes, narrating each look.

    Streamed rather than awaited: the loop can spend half a minute across
    several reads, and a spinner for half a minute is indistinguishable from a
    hang. Each step is sent as it happens, so the wait says what it is doing.
    """
    me = getattr(request.state, "user", None)

    def frames():
        # The loop runs on its own thread and posts each step to a queue as it
        # happens. Collecting them and replaying afterwards was the obvious
        # shape and the wrong one: the reader waits the whole thirty seconds and
        # then receives the narration all at once, which is exactly the silence
        # the narration exists to avoid.
        import queue as _q
        import threading as _t
        box: _q.Queue = _q.Queue()
        # Set when this generator is closed — which is what a closed rail, a
        # reloaded page or a second question looks like from here. The worker is
        # a daemon thread, so without it an abandoned question still spent its
        # whole budget of model calls and cluster reads.
        gone = _t.Event()

        def work():
            try:
                res = agent.run(me, [{"role": "user", "text": q}],
                                on_step=lambda line: box.put(("step", line)),
                                stop=gone)
                box.put(("answer", {"text": res["answer"], "steps": res["steps"],
                                    "proposals": res["proposals"]}))
            except agent.Abandoned:
                pass                    # nobody to tell; that is the point
            # {"error": …}, the shape /assistant/stream already sends. It was a
            # bare string here, so the two assistant streams disagreed about
            # what an error frame looks like — invisible today because the rail
            # only counts the frame, and a trap for whoever first tries to read
            # the reason out of one.
            except assistant.AiError as e:
                box.put(("error", {"error": str(e)}))
            except Exception as e:                            # noqa: BLE001
                box.put(("error",
                         {"error": f"the assistant failed: {str(e)[:200]}"}))
            finally:
                box.put((None, None))

        _t.Thread(target=work, name="assistant-agent", daemon=True).start()
        try:
            while True:
                try:
                    kind, payload = box.get(timeout=15)
                except _q.Empty:
                    # A slow read must not look like a dropped connection to a
                    # proxy sitting between the browser and here.
                    yield ": keepalive\n\n"
                    continue
                if kind is None:
                    return
                yield logs.sse(kind, payload)
        finally:
            gone.set()

    return StreamingResponse(frames(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/assistant/agent.json")
def assistant_agent_ready(request: Request):
    """Whether step-by-step answering is available to this person, so the rail
    can choose a path rather than trying and failing."""
    me = getattr(request.state, "user", None)
    cfg = assistant.config_for(me)
    return JSONResponse({
        "available": bool(assistant.usable(cfg)
                          and cfg.get("provider") == "anthropic"),
        "steps": agent.STEPS,
    })


@app.post("/assistant/propose")
async def assistant_propose(request: Request):
    """What an action would do, without doing it. Feeds the card in the rail."""
    me = getattr(request.state, "user", None)
    body = await request.json()
    try:
        return JSONResponse(aitools.propose(
            me, str(body.get("project", "")), str(body.get("cluster", "")),
            str(body.get("action", "")), body.get("args") or {}))
    except aitools.Denied as e:
        return JSONResponse({"denied": str(e)}, 200)


@app.post("/assistant/act")
async def assistant_act(request: Request):
    """Run a proposed action. Nothing reaches here without somebody clicking.

    The proposal is re-derived rather than trusted: what arrives is a cluster,
    an action name and its arguments, and every check runs again. A card that
    sat in a browser for ten minutes is a suggestion, not a permission slip.
    """
    me = getattr(request.state, "user", None)
    body = await request.json()
    try:
        res = await run_in_threadpool(
            aitools.execute, me, str(body.get("project", "")),
            str(body.get("cluster", "")), str(body.get("action", "")),
            body.get("args") or {}, str(body.get("confirm", "")),
            _client_ip(request))
        return JSONResponse(res)
    except aitools.Denied as e:
        return JSONResponse({"denied": str(e)}, 200)


@app.get("/clusters/scan/report")
def cluster_scan_report(request: Request, project: str = "", cluster: str = "",
                        fmt: str = "html"):
    """The audit as a file: JSON for a pipeline, CSV for a spreadsheet, or a
    self-contained HTML page for the person who asked for "the report"."""
    sel = store.get_cluster(project, cluster)
    if not sel:
        return RedirectResponse("/clusters?err=unknown cluster", 303)
    sel = {**sel, "id": cluster}
    name = sel.get("name", cluster)
    # the cached part: downloading a report should not re-scan the cluster
    data = clusterview.part(sel, "audit")
    header, rows = audit.rows(data)
    counted = data.get("counted") or {}
    summary = [(k, v) for k, v in (data.get("totals") or {}).items()]
    title = f"Cluster security audit · {name}"
    subtitle = (f"read through the Kubernetes API — nothing installed in the "
                f"cluster · {counted.get('pods', 0)} pods, "
                f"{counted.get('nodes', 0)} nodes · {data.get('at', '')}")
    base = re.sub(r"[^A-Za-z0-9._-]+", "-",
                  f"cluster-audit-{name}-{time.strftime('%Y%m%d-%H%M')}").strip("-")
    auth.audit(getattr(request.state, "user", None), "scan_report_exported",
               name, f"{fmt} · {len(rows)} rows", _client_ip(request))
    if fmt == "json":
        return Response(json.dumps(data, indent=2, default=str),
                        media_type="application/json",
                        headers={"Content-Disposition":
                                 f'attachment; filename="{base}.json"'})
    if fmt == "csv":
        return Response(audit.as_csv(header, rows), media_type="text/csv",
                        headers={"Content-Disposition":
                                 f'attachment; filename="{base}.csv"'})
    return Response(audit.as_html(title, subtitle, summary, header, rows),
                    media_type="text/html",
                    headers={"Content-Disposition":
                             f'attachment; filename="{base}.html"'})


@app.post("/clusters/access/create", response_class=HTMLResponse)
async def cluster_access_create(request: Request):
    """Create a cluster user, and hand back its kubeconfig once."""
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    sel = store.get_cluster(project, cid)
    if not sel:
        return RedirectResponse("/clusters?err=unknown cluster", 303)
    sel = {**sel, "id": cid}
    me = getattr(request.state, "user", None)
    created, err = None, ""
    try:
        if not kmanage.writable(sel):
            raise access.AccessError(kmanage.read_only_why("creating a user writes to it"))
        if (why := aitools.confirm_prod(project, cid, sel,
                                        str(f.get("confirm", "")))):
            raise access.AccessError(why)
        created = await run_in_threadpool(
            access.create, sel,
            name=str(f.get("name", "")),
            preset=str(f.get("preset", "")),
            namespaces=_csv(f.get("namespaces", "")),
            sa_namespace=str(f.get("sa_namespace", "") or "default"),
            duration=str(f.get("duration", "") or "8760h"),
            verbs=[k[5:] for k in f.keys() if k.startswith("verb_")],
            resources=_csv(f.get("resources", "")),
            cluster_wide_ok=bool(f.get("cluster_wide_ok")),
        )
        # the grant is audited; the token never is
        auth.audit(me, "cluster_user_created", sel.get("name", cid),
                   created["summary"], _client_ip(request))
    except access.AccessError as e:
        err = str(e)
        auth.audit(me, "cluster_user_refused", sel.get("name", cid),
                   f"{str(f.get('name',''))[:60]}: {err[:200]}", _client_ip(request))
    except Exception as e:                                    # noqa: BLE001
        err = f"{type(e).__name__}: {str(e)[:240]}"
    return _clusters_render(request, project, cid, "access", err=err,
                            created=created)


@app.post("/clusters/shell/run")
async def cluster_shell_run(request: Request):
    """Run a command and answer with JSON, so the console never reloads.

    Same validation, same audit trail and same production guard as the form
    version — the difference is only how the answer is delivered.
    """
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    raw, confirm = str(f.get("cmd", "")), str(f.get("confirm", "")).strip()
    # Same reasoning as /clusters/action: the console is the other way to run
    # kubectl, and _ws_user already demands this area for the terminal. A guard
    # written out per route is a guard that goes missing from one of them.
    me = _may(request, "manage")
    if not me:
        return JSONResponse(
            {"refused": "your roles do not include Cluster management"}, 403)
    sel = store.get_cluster(project, cid)
    if not sel:
        return JSONResponse({"refused": "unknown cluster"}, 404)
    sel = {**sel, "id": cid}
    ip = _client_ip(request)
    try:
        kind = kmanage.classify(kmanage.parse(raw))
        if kind == "write" and (why := aitools.confirm_prod(
                project, cid, sel, confirm, "in the confirmation box first")):
            raise kmanage.Refused(why)
        res = await run_in_threadpool(
            kmanage.run, sel, raw, allow_write=kmanage.writable(sel))
        auth.audit(me, f"kubectl_{res['kind']}", sel.get("name", cid),
                   f"exit {res['code']} · {res['display'][:300]}", ip)
        if res["kind"] == "write":
            clusterview.invalidate()
            fleet.invalidate()
        return JSONResponse(res)
    except kmanage.Refused as e:
        auth.audit(me, "kubectl_refused", sel.get("name", cid),
                   f"{str(e)[:150]} · {raw[:200]}", ip)
        return JSONResponse({"refused": str(e)})


@app.get("/clusters/shell/complete")
def cluster_shell_complete(request: Request, project: str = "", cluster: str = "",
                           text: str = "", ns: str = ""):
    """Tab completion, read from the cluster itself and briefly cached."""
    sel = store.get_cluster(project, cluster)
    if not sel:
        return JSONResponse({"items": [], "kind": "", "token": ""})
    return JSONResponse(kmanage.complete({**sel, "id": cluster}, text, ns))


@app.get("/clusters/shell/namespaces")
def cluster_shell_namespaces(project: str = "", cluster: str = ""):
    sel = store.get_cluster(project, cluster)
    if not sel:
        return JSONResponse([])
    return JSONResponse(kmanage.namespaces({**sel, "id": cluster}))


@app.post("/clusters/access/reissue", response_class=HTMLResponse)
async def cluster_access_reissue(request: Request):
    """Mint a new token for an existing user, for a lost kubeconfig."""
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    sel = store.get_cluster(project, cid)
    if not sel:
        return RedirectResponse("/clusters?err=unknown cluster", 303)
    sel = {**sel, "id": cid}
    me = getattr(request.state, "user", None)
    created, err = None, ""
    try:
        if not kmanage.writable(sel):
            raise access.AccessError(kmanage.read_only_why("minting a token writes to it"))
        if (why := aitools.confirm_prod(project, cid, sel,
                                        str(f.get("confirm", "")))):
            raise access.AccessError(why)
        created = await run_in_threadpool(
            access.reissue, sel, str(f.get("name", "")),
                                 str(f.get("sa_namespace", "")),
                                 str(f.get("duration", "") or "8760h"))
        auth.audit(me, "cluster_user_token_reissued", sel.get("name", cid),
                   created["summary"], _client_ip(request))
    except access.AccessError as e:
        err = str(e)
        auth.audit(me, "cluster_user_refused", sel.get("name", cid),
                   f"reissue {str(f.get('name',''))[:60]}: {err[:180]}",
                   _client_ip(request))
    except Exception as e:                                    # noqa: BLE001
        err = f"{type(e).__name__}: {str(e)[:240]}"
    return _clusters_render(request, project, cid, "access", err=err,
                            created=created)


@app.post("/clusters/access/revoke")
async def cluster_access_revoke(request: Request):
    """Delete a cluster user, which is what invalidates its token."""
    f = await request.form()
    project, cid = str(f.get("project", "")), str(f.get("cluster", ""))
    name, sa_ns = str(f.get("name", "")), str(f.get("sa_namespace", ""))
    sel = store.get_cluster(project, cid)
    to = f"/clusters?project={project}&cluster={cid}&tab=access"
    if not sel:
        return RedirectResponse("/clusters?err=unknown cluster", 303)
    sel = {**sel, "id": cid}
    me = getattr(request.state, "user", None)
    try:
        if not kmanage.writable(sel):
            raise access.AccessError(
                kmanage.read_only_why("revoking writes to it"))
        if (why := aitools.confirm_prod(project, cid, sel,
                                        str(f.get("confirm", "")))):
            raise access.AccessError(why)
        res = await run_in_threadpool(access.revoke, sel, name, sa_ns)
        auth.audit(me, "cluster_user_revoked", f"{sel.get('name')} · {sa_ns}/{name}",
                   "; ".join(f"{s['what']}: {s['detail'][:40]}"
                             for s in res["steps"])[:380], _client_ip(request))
        note = (f"{name} revoked" if res["ok"]
                else f"{name}: some cleanup failed — check the account is gone")
        return RedirectResponse(_with(to.split("?")[0], to.partition("?")[2],
                                      **({"msg": note} if res["ok"]
                                         else {"err": note})), 303)
    except access.AccessError as e:
        return RedirectResponse(_with(to.split("?")[0], to.partition("?")[2],
                                      err=str(e)), 303)


def _cluster_choices() -> list:
    """Every cluster the portal knows, for the console's picker and the two
    shortcuts in the top bar.

    Deliberately free of cluster calls: this renders in the top bar of every
    page, so it reads the database and the naming rules and nothing else.
    `writable` is a field on the record rather than a question for the API
    server, which is what makes that possible.
    """
    # Reachability from the snapshot the Overview already built, never a fresh
    # probe: this renders in the top bar of every page, and asking an
    # unreachable cluster is the one question that costs a timeout. peek()
    # returns None until a snapshot exists, and then every cluster is simply
    # not-known-bad — offering it is right, because refusing to offer a cluster
    # the portal has not looked at yet would hide a working one.
    snap = fleet.peek() or {}
    down = {c["cid"] for c in (snap.get("clusters") or [])
            if not c.get("reachable")}
    out = []
    for pid, p in store.projects().items():
        # Which of this project's clusters serve production, worked out ONCE per
        # project. Asking aitools.is_prod per cluster re-read the project and
        # re-derived its naming aliases every time — two SQL round trips and
        # several container copies per cluster, on every page render, because
        # this list is in the top bar. The mapping is a property of the project.
        aliases = repo.naming(pid)["aliases"]
        prod_cids = {mapped
                     for rg in (p.get("regions") or {}).values()
                     for env, mapped in (rg.get("env_clusters") or {}).items()
                     if mapped and config.is_prod_env(env, aliases)}
        for cid, c in (p.get("clusters") or {}).items():
            base = f"/clusters?project={pid}&cluster={cid}"
            out.append({
                "pid": pid, "cid": cid, "project": p.get("name", ""),
                "icon": p.get("icon", ""), "name": c.get("name", cid),
                "context": c.get("context", ""),
                "manage": kmanage.writable(c),
                "prod": cid in prod_cids,
                "down": cid in down,
                "url": f"{base}&tab=shell",
                # The troubleshooting pod is started by the dialog that already
                # exists on the cluster page — this only arrives with the flag
                # that opens it, so the shortcut and the button on the page are
                # the same code path rather than two that can drift apart.
                "ts_url": f"{base}&tab=overview&troubleshoot=1",
            })
    return sorted(out, key=lambda c: (c["project"], c["name"]))


def _cluster_is_prod(pid: str, cid: str) -> bool:
    """Whether any environment mapped to this cluster is a production one.

    Delegates: aitools owns it, because the assistant's propose()/execute() path
    and this one must agree about what production means.
    """
    return aitools.is_prod(pid, cid)


@app.get("/repos", response_class=HTMLResponse)
def repos_page(request: Request, msg: str = "", err: str = "", show: str = ""):
    """Operational view of every GitOps repo: clone health, the latest commit,
    env/service counts and quick actions. Connecting and editing a repo live on
    the settings page (linked per row) — this page is the status board, not a
    second copy of the config form.
    """
    view = {}
    tot = {"repos": 0, "connected": 0, "attention": 0, "disconnected": 0,
           "envs": 0, "svc": 0, "regions": 0}
    # Every region's repository state is three local git commands — branch,
    # porcelain status, last commit — and reading eight regions one after the
    # other was almost all of this page's time. They are independent reads of
    # different checkouts, so they go at once.
    pairs = [(pid, rgid) for pid, pr in store.projects().items()
             for rgid in (pr.get("regions") or {})]
    pre = dict(zip(pairs, fleet._pmap(
        lambda pr: _region_repo_groups(*pr), pairs,
        workers=min(8, max(1, len(pairs)))))) if pairs else {}
    for pid, p in store.projects().items():
        regions = {}
        for rgid, rg in p.get("regions", {}).items():
            envs = repo.list_envs(pid, rgid, include_hidden=True)
            # one row per (repository, branch), each carrying the environments
            # that read it — a region can span repositories now, and the board
            # has to say which environments come from which
            rows = []
            # _pmap turns a raised exception into None. A region silently
            # showing no repositories would be a status board quietly lying, so
            # a miss is read again here — and if it is going to raise, it
            # raises exactly where it used to.
            groups = pre.get((pid, rgid))
            if groups is None:
                groups = _region_repo_groups(pid, rgid)
            for g in groups:
                git = g["git"]
                if not g["url"]:
                    state = "disconnected"
                elif not git.get("cloned") or git.get("dirty"):
                    state = "attention"
                else:
                    state = "connected"
                rows.append({**g, "state": state,
                             "web_url": gitrepo.web_url(g["url"]),
                             "commit_url": gitrepo.commit_url(
                                 g["url"], git.get("sha", ""))})
                tot[state] += 1
                if g["url"]:
                    tot["repos"] += 1
            state = ("attention" if any(r["state"] == "attention" for r in rows)
                     else "connected" if any(r["state"] == "connected"
                                             for r in rows)
                     else "disconnected")
            tot["regions"] += 1
            tot["envs"] += len(envs)
            tot["svc"] += sum(len(f) for f in envs.values())
            regions[rgid] = {**rg, "envs": envs, "rows": rows, "state": state,
                             "svc": sum(len(f) for f in envs.values())}
        # attention first, then connected, then not-connected — the board reads
        # top-down as "what needs me"
        order = {"attention": 0, "connected": 1, "disconnected": 2}
        regions = dict(sorted(regions.items(),
                              key=lambda kv: order.get(kv[1]["state"], 3)))
        view[pid] = {**p, "region_view": regions}
    return templates.TemplateResponse(
        request, "repos.html",
        ctx(request, projects=view, stat=tot, msg=msg, err=err,
            show=show if show in ("connected", "attention", "disconnected") else "all"))


def _source_tabs(sources, active: str, href, counts=None, asked=None,
                 idle_labels=()) -> list:
    """One tab per source plus All, for the pages built on a source table.

    Three copies of this had appeared — timeline, radar, and the radar's own
    calendar page since folded into it — and they had begun to differ in which
    of them showed a count. `counts` of None means "not read", which the tab
    renders as no number at all rather than a zero it never checked.

    `asked` is the sources that were READ, and a source missing from it gets no
    tab. Pass every source the reader may see, not the subset this request
    filtered to: the radar passed the chosen kind, so picking one tab dropped
    all the others off the bar.
    """
    total = sum((counts or {}).values()) if counts is not None else None
    tabs = [{"key": "all", "label": "All",
             "icon": logos.glyph("layout-grid", 15), "idle": False,
             "count": total, "active": active == "all", "href": href("all")}]
    for key, (label, icon, _areas) in sources.items():
        if asked is not None and key not in asked and label not in idle_labels:
            continue
        tabs.append({
            "key": key, "label": label, "icon": logos.glyph(icon, 15),
            "count": (counts or {}).get(key) if (counts is not None
                                                 and (asked is None
                                                      or key in asked)) else None,
            "active": active == key, "href": href(key),
            "idle": label in idle_labels,
        })
    return tabs


# ── what changed ───────────────────────────────────────────────
@app.get("/timeline", response_class=HTMLResponse)
def timeline_page(request: Request, hours: int = timeline.DEFAULT_HOURS,
                  kind: list[str] = Query(default=[]), q: str = "",
                  at: str = "", span: int = timeline.DEFAULT_SPAN,
                  refresh: str = "", tab: str = "all"):
    """Every change from every connected system, on one clock.

    `at` centres the window on a moment rather than on now — the "what happened
    around this alert" question, which is the reason the page exists. It is read
    as local time because the only things that link here are this portal's own
    pages, which print local time.
    """
    me = _may(request, "timeline")
    if not me:
        return templates.TemplateResponse(request, "denied.html", ctx(request),
                                          status_code=403)
    centre = timeline.at(at, clock="local") if at else None
    # An unparseable `at` must not silently become "now": that would answer a
    # different question and look like it had answered the one asked.
    bad_at = bool(at) and centre is None
    hours = max(1, min(int(hours or timeline.DEFAULT_HOURS), timeline.MAX_HOURS))
    span = max(1, min(int(span or timeline.DEFAULT_SPAN), 24 * 60))
    # A tab is one source; "all" is every one of them. `kind` is still honoured
    # so links made before tabs existed keep working, and it wins when present.
    tab = tab if tab in timeline.SOURCES or tab == "all" else "all"
    picked = [k for k in kind if k in timeline.SOURCES]
    if picked:
        tab = picked[0] if len(picked) == 1 else "all"
    kinds = picked or (list(timeline.SOURCES) if tab == "all" else [tab])
    got = timeline.collect(me, hours=hours, kinds=kinds, centre=centre,
                           span=span, q=q, refresh=bool(refresh))

    def href(for_tab: str, centre_at: str = "", centre_span: int = 0) -> str:
        """The same question, asked of a different tab or a different moment."""
        parts = {"hours": hours, "q": q,
                 "at": centre_at or at,
                 "span": centre_span or (span if (centre_at or at) else 0)}
        out = urllib.parse.urlencode({k: v for k, v in parts.items() if v})
        if for_tab != "all":
            out += ("&" if out else "") + f"tab={urllib.parse.quote(for_tab)}"
        return f"/timeline?{out}" if out else "/timeline"

    # Built from SOURCES, so a source added tomorrow gets a tab without anyone
    # editing the template.
    tabs = _source_tabs(timeline.SOURCES, tab, href,
                        counts={**{k: 0 for k in got["asked"]},
                                **got["counts"]},
                        asked=None,
                        idle_labels=set(got["idle"]))
    tabs[0]["count"] = len(got["events"])
    return templates.TemplateResponse(
        request, "timeline.html",
        ctx(request, events=got["events"], days=timeline.group_by_day(got["events"]),
            notes=got["notes"] + (["that moment could not be read, so this is "
                                   "the last day instead"] if bad_at else []),
            hidden=got["hidden"], idle=got["idle"], counts=got["counts"],
            buckets=got["buckets"], tabs=tabs, tab=tab,
            stale=got.get("stale", 0), pending=got.get("pending", []),
            bucket_href=lambda c, s: href(tab, c, s),
            sources={k: {"label": lbl, "icon": logos.glyph(icon, 12)}
                     for k, (lbl, icon, _a) in timeline.SOURCES.items()},
            # the sources that actually contributed, not the ones that were
            # read: "8 changes from 5 sources" when four of them returned
            # nothing reads as coverage the page does not have
            shown=[k for k in kinds if got["counts"].get(k)],
            idle_keys=[k for k, (lbl, _i, _a) in timeline.SOURCES.items()
                       if lbl in got["idle"]],
            shown_labels=", ".join(
                timeline.SOURCES[k][0].lower() for k in kinds
                if k in timeline.SOURCES) or "changes",
            since_label=got["since"].strftime("%a %H:%M"),
            until_label=got["until"].strftime("%a %H:%M"),
            per_cluster=timeline.PER_CLUSTER_EVENTS,
            kinds=kinds, hours=hours, q=q,
            centred=centre.strftime("%Y-%m-%d %H:%M:%S") if centre else "",
            at_raw=at, span=span,
            refresh_url=(href(tab) + ("&" if "?" in href(tab) else "?")
                         + "refresh=1")))


# ── what runs out ──────────────────────────────────────────────
def _facet_label(options: list, value: str) -> str:
    """The readable name for a facet value, falling back to the value itself.

    A chip that reads "showing only: c-34f8b73f" is a filter somebody cannot
    recognise, which is nearly as bad as one they cannot see.
    """
    for o in options:
        if o["value"] == value:
            return o["label"]
    return value


def _expiry_view(request: Request, tab: str, horizon: int, q: str,
                 renewal: str, band: str, month: str, refresh: str,
                 project: str = "", cluster: str = "", region: str = "",
                 aside: str = ""):
    """The radar's data, or (None, None) when this person may not see it."""
    me = _may(request, "expiry")
    if not me:
        return None, None
    tab = tab if tab in expiry.SOURCES or tab == "all" else "all"
    kinds = list(expiry.SOURCES) if tab == "all" else [tab]
    horizon = horizon if horizon in [h for h, _l in expiry.horizons()] else 0
    got = expiry.collect(me, kinds=kinds, horizon=horizon, q=q,
                         renewal=renewal, band_only=band, month=month,
                         project=project, cluster=cluster, region=region,
                         refresh=bool(refresh), aside=bool(aside))
    return me, got


def _expiry_href(tab: str, horizon: int, q: str, renewal: str,
                 project: str = "", cluster: str = "", region: str = "",
                 aside: str = ""):
    """A link to this page with one thing changed.

    `band` and `month` are absent unless asked for: they are two ways of saying
    "this slice of the clock", and carrying one into a link that sets the other
    produces a filter nobody chose and an empty page.

    WHERE it lives is carried, unlike WHEN: narrowing to one cluster and then
    clicking a month should stay in that cluster, because those are two
    different questions about the same estate rather than two answers to one.
    """
    def build(**over):
        parts = {"tab": over.get("tab", tab),
                 "horizon": over.get("horizon", horizon),
                 "q": over.get("q", q), "renewal": over.get("renewal", renewal),
                 "project": over.get("project", project),
                 "cluster": over.get("cluster", cluster),
                 "region": over.get("region", region),
                 "band": over.get("band", ""), "month": over.get("month", ""),
                 # Carried like every other narrowing, so the "Not counted"
                 # tile links to exactly the rows it counted -- and so a tab
                 # or a search keeps its place when you look at them.
                 "aside": over.get("aside", aside)}
        if parts["tab"] == "all":
            parts.pop("tab")
        out = urllib.parse.urlencode({k: v for k, v in parts.items() if v})
        return f"/expiry?{out}" if out else "/expiry"
    return build


def _expiry_back(**extra) -> str:
    q = "&".join(f"{k}={urllib.parse.quote(str(v))}"
                 for k, v in extra.items() if v)
    return "/expiry" + (f"?{q}" if q else "")


@app.get("/expiry/blast", response_class=HTMLResponse)
async def expiry_blast(request: Request, pid: str = "", cid: str = "",
                       names: str = "", name: str = "", refresh: str = ""):
    """What stops working if this certificate is not renewed.

    Answered in the house pop-over rather than on the row, because it is one
    question about one certificate and the walk needs a cluster read the radar
    deliberately does not do for all twenty-four.

    GATED BY BOTH AREAS, and that is not belt-and-braces. Reading the radar is
    `expiry`; this reads a cluster's ingress objects, which is `clusters` --
    and it must also respect the per-cluster scope, or somebody scoped to one
    cluster could read another's host names through this window.
    """
    me = _may(request, "expiry")
    if me is None or not rbac.may_area(me, "clusters"):
        return HTMLResponse(
            "<p class='bl-note bad'>you do not have access to the cluster "
            "this certificate is on</p>", status_code=403)
    allowed = rbac.visible_clusters(me, "clusters")
    if allowed is not None and cid not in allowed:
        return HTMLResponse(
            "<p class='bl-note bad'>that cluster is outside what your account "
            "may read</p>", status_code=403)
    doms = [d.strip() for d in (names or "").split(",") if d.strip()]
    got = await run_in_threadpool(expiry.blast_radius, pid, cid, doms,
                                  refresh == "1")
    auth.audit(me, "expiry_blast_radius", name or (doms[0] if doms else "?"),
               f"{len(got.get('hosts') or [])} host(s) on "
               f"{got.get('cluster', '?')}", _client_ip(request))
    return templates.TemplateResponse(
        request, "_blast_body.html",
        ctx(request, b=got, cert=name, pid=pid, cid=cid, names=names))


@app.post("/expiry/aside")
async def expiry_set_aside(request: Request):
    """Stop counting one thing that does not need renewing.

    WHY A REASON IS REQUIRED. This is somebody asserting that a certificate the
    portal can see expiring does not matter, and that assertion changes the
    number everybody else reads on the overview. An assertion with no reason
    attached cannot be reviewed six months later by the person who inherits it
    -- and "why is this not counted?" is exactly the question that gets asked.
    """
    if (me := _may(request, "expiry")) is None:
        return templates.TemplateResponse(request, "denied.html", ctx(request),
                                          status_code=403)
    f = await request.form()
    reason = str(f.get("reason") or "").strip()
    row = {"kind": str(f.get("kind") or ""), "source": str(f.get("source") or ""),
           "where": str(f.get("where") or ""), "name": str(f.get("name") or "")}
    back = {"tab": f.get("tab") or "", "q": f.get("q") or ""}
    if not row["name"] or not row["kind"]:
        return RedirectResponse(_expiry_back(
            **back, err="that row could not be identified"), 303)
    if len(reason) < 4:
        return RedirectResponse(_expiry_back(
            **back, err="say why it does not need renewing — the number "
                        "everybody reads depends on it"), 303)
    # A refusal from the module is a sentence for the reader, not a 500: the
    # cap and the unknown-kind check both mean "this cannot be stored", and
    # the person is looking at a page that can say so.
    try:
        k = await run_in_threadpool(expiry.set_aside, row, reason,
                                    me.get("email", ""))
    except (ValueError, expiry.TooMany) as e:
        return RedirectResponse(_expiry_back(**back, err=str(e)), 303)
    auth.audit(me, "expiry_set_aside", f"{row['kind']}: {row['name']}",
               f"{row['where']} — {reason}", _client_ip(request))
    return RedirectResponse(_expiry_back(
        **back, msg=f"{row['name']} is no longer counted"), 303)


@app.post("/expiry/count-again")
async def expiry_count_again(request: Request):
    """Put one thing back on the clock."""
    if (me := _may(request, "expiry")) is None:
        return templates.TemplateResponse(request, "denied.html", ctx(request),
                                          status_code=403)
    f = await request.form()
    k = str(f.get("k") or "")
    name = str(f.get("name") or k)
    back = {"tab": f.get("tab") or "", "aside": f.get("aside") or ""}
    ok = await run_in_threadpool(expiry.count_again, k)
    if ok:
        auth.audit(me, "expiry_count_again", name, "back on the clock",
                   _client_ip(request))
    return RedirectResponse(_expiry_back(
        **back, msg=(f"{name} is counted again" if ok
                     else "that one was not set aside")), 303)


@app.get("/expiry", response_class=HTMLResponse)
async def expiry_page(request: Request, tab: str = "all", horizon: int = 0,
                      q: str = "", renewal: str = "", band: str = "",
                      month: str = "", refresh: str = "", project: str = "",
                      cluster: str = "", region: str = "", aside: str = "",
                      msg: str = "", err: str = ""):
    """Everything that runs out, soonest first, with how it renews."""
    me, got = await run_in_threadpool(
        _expiry_view, request, tab, horizon, q, renewal, band, month, refresh,
        project, cluster, region, aside)
    if me is None:
        return templates.TemplateResponse(request, "denied.html", ctx(request),
                                          status_code=403)
    href = _expiry_href(tab, horizon, q, renewal, project, cluster, region,
                        aside)
    tabs = _source_tabs(expiry.SOURCES, tab, lambda k: href(tab=k),
                        counts=got["counts"], asked=got["asked"])
    tabs[0]["count"] = len(got["all_rows"])
    here = href(band=band, month=month)
    # what is currently narrowing the list, each with the link that removes it —
    # a filter you cannot see is a filter you cannot undo, and the tiles and the
    # chart make it easy to arrive at three of them at once
    chips = [c for c in (
        {"label": expiry.month_label(month), "off": href(band=band)}
        if month else None,
        {"label": dict((k, lbl) for k, lbl, _lo, _hi in expiry.BANDS).get(band, band),
         "off": href(month=month)} if band else None,
        {"label": dict(expiry.horizons()).get(horizon, ""),
         "off": href(band=band, month=month, horizon=0)} if horizon else None,
        {"label": {"manual": "needs a person", "automatic": "renews itself",
                   "unknown": "renewal unknown"}.get(renewal, renewal),
         "off": href(band=band, month=month, renewal="")} if renewal else None,
        {"label": f"“{q}”", "off": href(band=band, month=month, q="")}
        if q else None,
        # Named by the estate's word for the thing, not by its id: "showing
        # only: p-3ca8e84d" tells nobody anything.
        {"label": _facet_label(got["facets"]["projects"], project),
         "off": href(band=band, month=month, project="")} if project else None,
        {"label": _facet_label(got["facets"]["clusters"], cluster),
         "off": href(band=band, month=month, cluster="")} if cluster else None,
        {"label": region, "off": href(band=band, month=month, region="")}
        if region else None,
    ) if c]
    return templates.TemplateResponse(
        request, "expiry.html",
        ctx(request, rows=got["rows"], groups=expiry.group_by_band(got["rows"]),
            summary=got["summary"], notes=got["notes"], hidden=got["hidden"],
            pending=got.get("pending", []), plan=expiry.by_month(got["scope"]),
            tabs=tabs, tab=tab, horizon=horizon, q=q, renewal=renewal,
            band=band, month=month, chips=chips,
            aside=got.get("aside", False),
            aside_count=got.get("aside_count", 0),
            msg=msg, err=err,
            stale=got["stale"], bands=expiry.BANDS,
            horizons=expiry.horizons(), href=href,
            sources={k: {"label": lbl, "icon": logos.glyph(icon, 13)}
                     for k, (lbl, icon, _a) in expiry.SOURCES.items()},
            # the two breakdowns beside the ring: what kind of thing, and where
            # it lives. Sorted here, and only what has rows — a facet of zeroes
            # is a list of places with no work in them.
            by_source=sorted(
                [{"key": k, "label": expiry.SOURCES[k][0], "n": n}
                 for k, n in got["counts"].items() if n],
                key=lambda s: -s["n"]),
            places=expiry.places(got["scope"], top=5),
            # f_* because `project` is a base.html context key — ctx() refuses
            # the clash rather than letting the sidebar quietly lose its own
            # value. The trio is renamed together so the template reads as one
            # thing rather than one renamed field beside two that were not.
            facets=got["facets"], f_project=project, f_cluster=cluster,
            f_region=region,
            scoped=len(got["scope"]),
            word=expiry.days_word,
            refresh_url=here + ("&" if "?" in here else "?") + "refresh=1"))


# ── setup wizard RETIRED ────────────────────────────────────────
# The plain Settings forms already cover project → region → repo → cluster →
# mapping, so the multi-step wizard was redundant. /setup (and any old link or
# bookmark) now just redirects to Settings → Projects, which has every add form.
@app.get("/setup")
def wizard(request: Request, pid: str = ""):
    return RedirectResponse("/settings/projects" + (f"#{pid}" if pid else ""), 303)


@app.get("/clusters/related", response_class=HTMLResponse)
def cluster_related(request: Request, project: str = "", cluster: str = "",
                    namespace: str = "", name: str = "", kind: str = "",
                    refresh: str = ""):
    """Everything in a namespace that belongs to one workload.

    The matcher is the service page's — svcview.cluster_side reads the namespace
    once and claims each object for a name by its own name, its labels and its
    owner. Reused rather than rewritten, because "which ConfigMap belongs to
    bff-backoffice" has exactly one right answer and two implementations of it
    would drift.

    Read-only, so it is gated on the clusters area rather than on management: the
    reason to open this is to find out what a workload is made of.
    """
    sel, why = _cluster_read(request, project, cluster)
    if why:
        return templates.TemplateResponse(
            request, "cluster_related.html",
            ctx(request, pid=project, cid=cluster, err=why, name=name,
                namespace=namespace, kind=kind, side=None), status_code=403)
    side = svcview.cluster_side(sel, namespace, name, {}, refresh=bool(refresh))
    # The pods too, on the page rather than behind a link to it. A workload's pods
    # ARE part of what it is made of, and the reason to open this page is usually
    # one of them — sending the reader somewhere else for the most-wanted half of
    # the answer is the kind of split that makes a page feel like an index.
    pods = [p for p in ((clusterview.part(sel, "pods", refresh=bool(refresh))
                         or {}).get("pods") or [])
            if p.get("namespace") == namespace
            and (p.get("workload") == name or not name)]
    pods.sort(key=lambda p: (p.get("healthy", True), p.get("name", "")))
    return templates.TemplateResponse(
        request, "cluster_related.html",
        ctx(request, pid=project, cid=cluster, sel=sel, name=name,
            namespace=namespace, kind=kind or "workload", side=side, pods=pods,
            err=side.get("error", ""),
            writable=kmanage.writable(sel),
            is_prod=_cluster_is_prod(project, cluster)))


# ── Ansible: playbooks, an inventory, and every run ────────────
# The page is three sections behind sub-tabs; the run window is what does the
# work. Everything that changes a host goes through one POST — /ansible/run —
# which is also the only place the `ansible_run` area is checked, so there is a
# single line to read to know who may change a machine.
def _ansible_back(sec: str = "", **extra) -> str:
    """Back to the section that was being worked in — and to the right card.

    The fragment matters with more than two groups: adding a host reloaded the
    page at the top, so the row you had just typed was somewhere below the fold
    and the flash message was the only sign anything had happened.
    """
    group = extra.get("group") or ""
    q = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in extra.items() if v)
    return (f"/ansible?sec={sec or 'playbooks'}" + (f"&{q}" if q else "")
            + (f"#g-{group}" if group else ""))


def _may_run(request: Request) -> str:
    """Empty when this person may start a run, otherwise the reason."""
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "ansible_run"):
        return ("your role may read playbooks but not run them — that needs "
                "“Ansible: run playbooks”")
    return ""


def _group_url(gid: str, **extra) -> str:
    """A group's own page. Everything about one group happens there now."""
    q = "&".join(f"{k}={urllib.parse.quote(str(v))}"
                 for k, v in extra.items() if v)
    return f"/ansible/groups/{gid}" + (f"?{q}" if q else "")


# What each tile at the top of the page narrows the run list to. The tile and the
# filter read the same table through the same names, so a tile cannot promise a
# number the list then disagrees with — the fault this shape avoids is the one the
# expiry radar had.
RUN_STATES = {"running": ("running",), "failed": ("failed", "unreachable"),
              "ok": ("ok",)}


def _place_options() -> list:
    """The portal's projects and their regions, shaped for the place selects."""
    return [{"id": k, "name": v["name"],
             "regions": [{"id": rk, "name": rv["name"]}
                         for rk, rv in (v.get("regions") or {}).items()]}
            for k, v in store.projects().items()]


def _region_options() -> list:
    """Every region the portal knows, flattened for the AWS-style region picker —
    each carries its project so the label can disambiguate same-named regions."""
    out = []
    for pid, p in store.projects().items():
        for rid, r in (p.get("regions") or {}).items():
            out.append({"id": rid, "pid": pid, "name": r["name"], "project": p["name"]})
    return sorted(out, key=lambda x: (x["project"].lower(), x["name"].lower()))


@app.get("/ansible", response_class=HTMLResponse)
def ansible_page(request: Request, sec: str = "", msg: str = "", err: str = "",
                 pb: str = "", group: str = "", state: str = "",
                 day: str = "", ran: str = "", proj: str = "", reg: str = ""):
    """Playbooks, inventory, runs. One read of each, then one render.

    `day` and `ran` narrow the run list to one day or one playbook's runs —
    they exist because the overview's charts link here, and a chart column
    that says "click a day" has to open that day, not the whole history.
    `ran` matches the recorded NAME, not the playbook id, because the chart
    counts by name: a playbook deleted and recreated keeps one bar, and the
    bar's link must open exactly the runs it counted.
    """
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day or ""):
        day = ""
    runs = ansible.runs(120)
    if state in RUN_STATES:
        runs = [r for r in runs if r.get("status") in RUN_STATES[state]]
        sec = "runs"
    if day:
        runs = [r for r in runs if (r.get("started") or "")[:10] == day]
        sec = "runs"
    if ran:
        runs = [r for r in runs if (r.get("pb_name") or "") == ran]
        sec = "runs"
    # The page's own AWS-style region picker (`reg` in the query string, so a
    # filtered view is a URL): one region id, grouped by project in the menu,
    # "" = every region. Ansible and Provisioning are the two pages that keep
    # this — a portal-wide filter was built and reverted on request.
    region_opts = _region_options()
    if reg not in {r["id"] for r in region_opts}:
        reg = ""

    def _in_region(rgid: str) -> bool:
        return not reg or rgid == reg

    playbooks_l = [r for r in ansible.playbooks() if _in_region(r.get("rgid", ""))]
    groups_l = [g for g in ansible.groups() if _in_region(g.get("rgid", ""))]
    schedules_l = [s for s in ansible.schedules() if _in_region(s.get("rgid", ""))]
    runs = [r for r in runs if _in_region(r.get("rgid", ""))]
    return templates.TemplateResponse(
        request, "ansible.html",
        ctx(request, sec=sec, msg=msg, err=err, focus_pb=pb, focus_group=group,
            playbooks=playbooks_l, groups=groups_l, schedules=schedules_l,
            runs=runs, state=state if state in RUN_STATES else "",
            day=day, ran=ran, reg=reg, region_opts=region_opts,
            region_label=(next((r["name"] for r in region_opts
                                if r["id"] == reg), "All regions")
                          if reg else "All regions"),
            until=ansible.until_words,
            summary=ansible.summary(reg),
            # Only for the overview: counting five hundred rows to draw a chart
            # nobody is looking at is work for nothing on the other three tabs.
            # Scoped by the portal filter, like every figure above it.
            hist=(ansible.history(reg=reg)
                  if (sec or "overview") == "overview" else None),
            cfg=ansible.config(), tool=ansible.tool(),
            may_run=not _may_run(request), why_no_run=_may_run(request)))


@app.post("/ansible/run/delete")
async def ansible_delete_run(request: Request):
    """Forget one recorded run.

    Behind `ansible_run` rather than behind reading: the record of what was done
    to which machines is the audit somebody else may be relying on, so removing
    it belongs with the permission to do things, not with the permission to look.
    """
    f = await request.form()
    if (why := _may_run(request)):
        return RedirectResponse(_ansible_back("runs", err=why), 303)
    me = getattr(request.state, "user", None)
    try:
        got = await run_in_threadpool(ansible.delete_run,
                                      str(f.get("run_id") or "").strip())
    except ansible.Refused as e:
        return RedirectResponse(_ansible_back("runs", err=str(e)), 303)
    if not got:
        return RedirectResponse(_ansible_back("runs", err="that run is gone"), 303)
    auth.audit(me, "ansible_run_deleted",
               f"{got.get('pb_name') or '—'} → {got.get('group_name') or '—'}",
               f"was {got.get('status')}", _client_ip(request))
    return RedirectResponse(_ansible_back("runs", msg="run deleted"), 303)


@app.post("/ansible/runs/clear")
async def ansible_clear_runs(request: Request):
    """Delete a whole class of finished run. Never one still going."""
    f = await request.form()
    if (why := _may_run(request)):
        return RedirectResponse(_ansible_back("runs", err=why), 303)
    which = str(f.get("which") or "finished")
    me = getattr(request.state, "user", None)
    try:
        gone = await run_in_threadpool(ansible.clear_runs, which)
    except ansible.Refused as e:
        return RedirectResponse(_ansible_back("runs", err=str(e)), 303)
    auth.audit(me, "ansible_runs_cleared", which, f"{gone} run(s)",
               _client_ip(request))
    return RedirectResponse(
        _ansible_back("runs", msg=f"{gone} run(s) deleted"
                      if gone else "there was nothing to delete"), 303)


@app.get("/ansible/schedules/{sid}", response_class=HTMLResponse)
def ansible_schedule_page(request: Request, sid: str, msg: str = "",
                          err: str = ""):
    """One schedule, on its own page. `new` is the same page, empty."""
    s = None if sid == "new" else ansible.schedule(sid)
    if sid != "new" and not s:
        return RedirectResponse(_ansible_back("schedules",
                                              err="that schedule is gone"), 303)
    from datetime import datetime as _dt
    return templates.TemplateResponse(
        request, "ansible_schedule.html",
        ctx(request, s=s, msg=msg, err=err,
            playbooks=ansible.playbooks(), groups=ansible.groups(),
            days=ansible.DAYS, cfg=ansible.config(),
            tzname=_dt.now().astimezone().tzname() or "the portal's local time",
            may_run=not _may_run(request), why_no_run=_may_run(request)))


@app.post("/ansible/schedule/save")
async def ansible_save_schedule(request: Request):
    """Create or change a schedule. Behind `ansible_run`: a schedule IS runs,
    just later — a role that may not press the button may not wire a clock to
    it either."""
    f = await request.form()
    sid = (f.get("sid") or "").strip()
    if (why := _may_run(request)):
        return RedirectResponse(_ansible_back("schedules", err=why), 303)
    me = getattr(request.state, "user", None)
    try:
        sid = ansible.save_schedule(sid, {k: str(v) for k, v in f.items()},
                                    (me or {}).get("email", ""))
    except ansible.Refused as e:
        back = (f"/ansible/schedules/{urllib.parse.quote(sid or 'new')}"
                f"?err={urllib.parse.quote(str(e))}")
        return RedirectResponse(back, 303)
    got = ansible.schedule(sid) or {}
    auth.audit(me, "ansible_schedule_saved", f.get("name") or sid,
               f"{ansible.cadence_words(got)} · "
               f"{'check' if got.get('check_mode') else 'REAL'}",
               _client_ip(request))
    return RedirectResponse(
        _ansible_back("schedules",
                      msg=f"scheduled — next run {ansible.until_words(got.get('next_at') or '')}"),
        303)


@app.post("/ansible/schedule/delete")
async def ansible_delete_schedule(request: Request):
    f = await request.form()
    if (why := _may_run(request)):
        return RedirectResponse(_ansible_back("schedules", err=why), 303)
    me = getattr(request.state, "user", None)
    got = ansible.delete_schedule((f.get("sid") or "").strip())
    if not got:
        return RedirectResponse(_ansible_back("schedules",
                                              err="already gone"), 303)
    auth.audit(me, "ansible_schedule_deleted", got.get("name", ""),
               "", _client_ip(request))
    return RedirectResponse(_ansible_back("schedules",
                                          msg=f"{got['name']} deleted"), 303)


@app.post("/ansible/schedule/toggle")
async def ansible_toggle_schedule(request: Request):
    f = await request.form()
    if (why := _may_run(request)):
        return RedirectResponse(_ansible_back("schedules", err=why), 303)
    me = getattr(request.state, "user", None)
    on = bool(f.get("enabled"))
    got = ansible.toggle_schedule((f.get("sid") or "").strip(), on)
    if not got:
        return RedirectResponse(_ansible_back("schedules",
                                              err="that schedule is gone"), 303)
    auth.audit(me, "ansible_schedule_toggled", got.get("name", ""),
               "resumed" if on else "paused", _client_ip(request))
    return RedirectResponse(
        _ansible_back("schedules",
                      msg=f"{got['name']} {'resumed' if on else 'paused'}"), 303)


@app.get("/ansible/groups/{gid}/terminal", response_class=HTMLResponse)
def ansible_host_terminal_page(request: Request, gid: str, host: str = "",
                               confirm: str = ""):
    """The page that holds a terminal on one host of a group.

    A GET so it can be opened, bookmarked and refreshed; the socket it opens
    carries the real gate. The production confirm is collected HERE — a plain
    field on the way in — and passed to the socket, so the answer is given by a
    person looking at the page rather than typed blind into a query string.
    """
    if (why := _may_run(request)):
        return RedirectResponse(_ansible_back("inventory", err=why), 303)
    g = ansible.group(gid)
    if not g:
        return RedirectResponse(_ansible_back("inventory",
                                              err="that group is gone"), 303)
    if host not in {h["name"] for h in g["hosts"]}:
        return RedirectResponse(_group_url(gid, err="no such host in this group"),
                                303)
    # A production group asks for its name before the terminal opens. Shown as a
    # small gate page rather than refused, because the answer is one field.
    if g.get("is_prod") and confirm != g["name"]:
        return templates.TemplateResponse(
            request, "ansible_term_confirm.html",
            ctx(request, g=g, host=host, bad=bool(confirm)))
    return templates.TemplateResponse(
        request, "ansible_terminal.html",
        ctx(request, g=g, host=host, confirm=confirm))


def _group_render(request: Request, g, msg: str = "", err: str = "",
                  gid: str = ""):
    """The group page, from a group dict rather than from an id.

    Extracted so a REFUSED SAVE can render it with the values the person just
    typed. A save that fails validation used to answer 303 -- to the inventory
    list when creating, which is a thirteen-field form thrown away and an error
    about a page you are no longer on. See CLAUDE.md on why a recoverable
    validation failure re-renders instead of redirecting.
    """
    if g:
        g["env_label"] = pam.env_label(g.get("env", ""))
        g["env_tone"] = pam.env_tone(g.get("env", ""))
        for h in g.get("hosts", []):
            eff = (h.get("env") or "").strip() or g.get("env", "")
            h["env_label"] = pam.env_label(eff)
            h["env_tone"] = pam.env_tone(eff)
    stored = bool(g and g.get("id"))
    return templates.TemplateResponse(
        request, "ansible_group.html",
        ctx(request, g=g, msg=msg, err=err,
            inventory=ansible.inventory_text(g) if stored else "",
            # what the stored key is, or what is wrong with it — on the page that
            # can replace it, rather than in the middle of a failed run
            key=ansible.key_health(g) if stored else {},
            # only on a group's own page, and only when there is a group to add
            # them to: the list page was reading five hundred assets to render a
            # picker nobody had opened
            assets_free=assets.search(limit=500)["rows"] if stored else [],
            runs=ansible.runs(40, group_id=gid or (g or {}).get("id", ""))
                 if stored else [],
            place_options=_place_options(),
            playbooks=ansible.playbooks() if stored else [],
            cfg=ansible.config(), tool=ansible.tool(), env_suggest=pam.ENV_SUGGEST,
            may_run=not _may_run(request), why_no_run=_may_run(request)))


@app.get("/ansible/groups/{gid}", response_class=HTMLResponse)
def ansible_group_page(request: Request, gid: str, msg: str = "", err: str = ""):
    """One group of hosts, on its own page. `new` is the same page, empty.

    It used to be a card in a list, holding a thirteen-field form behind a
    disclosure — so the page that answers "what am I running against" was also
    the page that asks for a private key, and the list of groups was buried under
    however many forms were open. A group is a thing with a name; things with
    names get pages, the way a playbook already did.
    """
    g = None if gid == "new" else ansible.group(gid)
    if gid != "new" and not g:
        return RedirectResponse(_ansible_back("inventory",
                                              err="that group is gone"), 303)
    return _group_render(request, g, msg=msg, err=err, gid=gid)


@app.get("/ansible/playbooks/{pb_id}", response_class=HTMLResponse)
def ansible_editor(request: Request, pb_id: str, msg: str = "", err: str = ""):
    """One playbook, in an editor. `new` is the same page with nothing in it."""
    pb = None if pb_id == "new" else ansible.playbook(pb_id)
    if pb_id != "new" and not pb:
        return RedirectResponse(_ansible_back(err="that playbook is gone"), 303)
    return templates.TemplateResponse(
        request, "ansible_playbook.html",
        ctx(request, pb=pb, msg=msg, err=err, groups=ansible.groups(),
            place_options=_place_options(), env_suggest=pam.ENV_SUGGEST,
            revs=ansible.revisions(pb_id) if pb else [],
            runs=ansible.runs(25, pb_id) if pb else [],
            tool=ansible.tool(), cfg=ansible.config(),
            may_run=not _may_run(request), why_no_run=_may_run(request),
            example=ansible.EXAMPLE))


@app.post("/ansible/playbook/save")
async def ansible_save_playbook(request: Request):
    """Save, then say whether ansible can parse it.

    The check never blocks the save. A playbook referencing a role that lives on
    the host rather than in this container fails `--syntax-check` while being
    perfectly correct, and an editor that refuses to keep your work because of
    that is an editor nobody can use.
    """
    f = await request.form()
    me = getattr(request.state, "user", None)
    who = (me or {}).get("email", "")
    try:
        pb_id = ansible.save_playbook(
            (f.get("pb_id") or "").strip(), f.get("name") or "",
            f.get("body") or "", f.get("notes") or "", who,
            group_id=f.get("group_id") or "",
            pid=f.get("pid") or "", rgid=f.get("rgid") or "",
            env=f.get("env") or "")
    except ansible.Refused as e:
        return RedirectResponse(
            f"/ansible/playbooks/{urllib.parse.quote(f.get('pb_id') or 'new')}?err={urllib.parse.quote(str(e))}",
            303)
    auth.audit(me, "ansible_playbook_saved", f.get("name") or pb_id,
               f"{len(f.get('body') or '')} bytes", _client_ip(request))
    syn = ansible.syntax_check(f.get("body") or "")
    if syn["checked"] and not syn["ok"]:
        first = (syn["error"] or "").strip().splitlines()[0][:160]
        return RedirectResponse(
            f"/ansible/playbooks/{pb_id}?err="
            + urllib.parse.quote(f"Saved, but ansible cannot parse it: {first}"), 303)
    return RedirectResponse(f"/ansible/playbooks/{pb_id}?msg="
                            + urllib.parse.quote("Saved" + (" · ansible parses it"
                                               if syn["checked"] else "")), 303)


@app.post("/ansible/playbook/check")
async def ansible_check_playbook(request: Request):
    """`--syntax-check` on what is in the editor, without saving it."""
    f = await request.form()
    return JSONResponse(ansible.syntax_check(f.get("body") or ""))


@app.post("/ansible/playbook/restore")
async def ansible_restore_playbook(request: Request):
    f = await request.form()
    pb_id, rev = (f.get("pb_id") or "").strip(), (f.get("rev_id") or "").strip()
    pb, body = ansible.playbook(pb_id), ansible.revision_body(rev)
    me = getattr(request.state, "user", None)
    if not pb or not body:
        return RedirectResponse(_ansible_back(err="that version is gone"), 303)
    ansible.save_playbook(pb_id, pb["name"], body, pb.get("notes") or "",
                          (me or {}).get("email", ""),
                          group_id=pb.get("group_id") or "")
    auth.audit(me, "ansible_playbook_restored", pb["name"], rev,
               _client_ip(request))
    return RedirectResponse(f"/ansible/playbooks/{pb_id}?msg="
                            + urllib.parse.quote("that version is now the current one"), 303)


@app.post("/ansible/playbook/delete")
async def ansible_delete_playbook(request: Request):
    f = await request.form()
    pb = ansible.playbook((f.get("pb_id") or "").strip())
    me = getattr(request.state, "user", None)
    if not pb:
        return RedirectResponse(_ansible_back(err="that playbook is gone"), 303)
    ansible.delete_playbook(pb["id"])
    auth.audit(me, "ansible_playbook_deleted", pb["name"],
               "its runs are kept", _client_ip(request))
    return RedirectResponse(
        _ansible_back(msg=f"{pb['name']} deleted — its runs are kept"), 303)


@app.post("/ansible/group/save")
async def ansible_save_group(request: Request):
    f = await request.form()
    me = getattr(request.state, "user", None)
    try:
        gid = ansible.save_group((f.get("gid") or "").strip(), {
            "name": f.get("name"), "notes": f.get("notes"),
            "ssh_user": f.get("ssh_user"), "ssh_port": f.get("ssh_port"),
            "become_root": f.get("become_root"),
            "no_host_key_check": f.get("no_host_key_check"),
            "group_vars": f.get("group_vars"), "key": f.get("key"),
            "key_path": f.get("key_path"), "drop_key": f.get("drop_key"),
            "pid": f.get("pid"), "rgid": f.get("rgid"),
            "is_prod": f.get("is_prod")}, (me or {}).get("email", ""))
    except ansible.Refused as e:
        # RE-RENDERED WITH WHAT WAS TYPED, not redirected. This used to answer
        # 303 -- to the group's page when editing, and to the INVENTORY LIST
        # when creating. Reported, and it is the worst version of the mistake:
        # somebody filled in a thirteen-field form, one field failed, and they
        # were thrown out to a list with a flash message about a page they were
        # no longer on and everything they had written gone.
        #
        # A redirect re-reads the group from the database, so it cannot show a
        # submission -- which is exactly why validation failures must not use
        # one. See CLAUDE.md, "a validation failure re-renders the form".
        gid = (f.get("gid") or "").strip()
        stored = ansible.group(gid) if gid else None
        # The submitted values, over whatever is stored, so an edit shows the
        # attempt rather than the row it failed to become. `hosts` is the
        # pasted block, which is the most expensive thing on this form to lose.
        g = dict(stored or {})
        g.setdefault("hosts", [])
        g.update({
            "id": gid, "name": f.get("name") or "", "notes": f.get("notes") or "",
            "ssh_user": f.get("ssh_user") or "", "ssh_port": f.get("ssh_port") or "",
            "become_root": bool(f.get("become_root")),
            "no_host_key_check": bool(f.get("no_host_key_check")),
            "group_vars": f.get("group_vars") or "",
            "key_path": f.get("key_path") or "",
            "pid": f.get("pid") or "", "rgid": f.get("rgid") or "",
            "is_prod": bool(f.get("is_prod")),
            "hosts_text": f.get("hosts") or "",
        })
        return _group_render(request, g, err=str(e), gid=gid)
    # The key itself is never audited, only that one arrived: an audit trail is
    # read by more people than the settings page is.
    auth.audit(me, "ansible_group_saved", f.get("name") or gid,
               "with a new key" if f.get("key") else "", _client_ip(request))
    note = "group saved"
    # Hosts pasted into the same form. A group with no hosts cannot be run
    # against, so making somebody save twice to get one was a step for nothing.
    if (f.get("hosts") or "").strip():
        added, skipped = ansible.add_hosts_text(
            gid, f.get("hosts"), (me or {}).get("email", ""))
        note = f"group saved · {added} host(s) added"
        if skipped:
            note += f" · {len(skipped)} skipped: " + "; ".join(skipped[:3])
    # And the key, in the same save. Making a group, giving it hosts and getting
    # key access onto them was three visits to two pages; a password typed here
    # does all three, against every host at once.
    if (f.get("password") or "").strip():
        if (why := _may_run(request)):
            return RedirectResponse(_group_url(gid, err=f"{note}, but {why}"), 303)
        try:
            got = await run_in_threadpool(
                ansible.install_key, gid, str(f.get("ssh_user") or ""),
                str(f.get("password") or ""), (me or {}).get("email", ""),
                str(f.get("confirm") or ""), str(f.get("key_type") or ""),
            # the ticked rows, which may be none — and none means every host
            [str(v) for v in f.getlist("only_hosts") if str(v).strip()])
        except ansible.Refused as e:
            return RedirectResponse(_group_url(gid, err=f"{note} — the key was "
                                                        f"not installed: {e}"), 303)
        bad = [r for r in got["rows"]
               if r["state"] not in ("installed", "already")]
        note += (f" · {got['ok']} of {got['total']} host(s) now reachable by key")
        if bad:
            note += " · " + "; ".join(f"{r['name']}: {r['note']}" for r in bad[:3])
            return RedirectResponse(_group_url(gid, err=note), 303)
    return RedirectResponse(_group_url(gid, msg=note), 303)


@app.post("/ansible/group/delete")
async def ansible_delete_group(request: Request):
    f = await request.form()
    g = ansible.group((f.get("gid") or "").strip())
    me = getattr(request.state, "user", None)
    if not g:
        return RedirectResponse(_ansible_back("inventory", err="already gone"), 303)
    ansible.delete_group(g["id"])
    auth.audit(me, "ansible_group_deleted", g["name"],
               f"{len(g['hosts'])} host(s)", _client_ip(request))
    return RedirectResponse(_ansible_back("inventory",
                                          msg=f"{g['name']} deleted"), 303)


@app.post("/ansible/group/keys")
async def ansible_install_key(request: Request):
    """Put the group's public key on its hosts, using a password once.

    The password is read out of the form, handed to ssh through a terminal, and
    dropped — it is never stored, never audited and never written to disk. What
    remains is a key the run path already knows how to use.

    Gated on `ansible_run` rather than on reading: this writes to
    authorized_keys on every host in the group, which is a change to those
    machines and belongs behind the same permission as running a playbook.
    """
    f = await request.form()
    gid = (f.get("gid") or "").strip()
    if (why := _may_run(request)):
        return RedirectResponse(_group_url(gid, err=why), 303)
    me = getattr(request.state, "user", None)
    try:
        got = await run_in_threadpool(
            ansible.install_key, gid, str(f.get("ssh_user") or ""),
            str(f.get("password") or ""), (me or {}).get("email", ""),
            str(f.get("confirm") or ""), str(f.get("key_type") or ""))
    except ansible.Refused as e:
        return RedirectResponse(_group_url(gid, err=str(e)), 303)
    bad = [r for r in got["rows"] if r["state"] not in ("installed", "already")]
    note = (f"{got['ok']} of {got['total']} host(s) now reachable by key"
            + (" · a key was generated for this group" if got["generated"] else ""))
    if bad:
        # Named, not counted: "2 of 3 worked" without saying which one did not is
        # a result somebody has to go and re-derive by hand.
        note += " · " + "; ".join(f"{r['name']}: {r['note']}" for r in bad[:3])
        return RedirectResponse(_group_url(gid, err=note), 303)
    return RedirectResponse(_group_url(gid, msg=note), 303)


@app.post("/ansible/host/add")
async def ansible_add_host(request: Request):
    f = await request.form()
    gid = (f.get("gid") or "").strip()
    try:
        ansible.add_host(gid, f.get("name") or "", f.get("address") or "",
                         ((getattr(request.state, "user", None) or {})
                          .get("email", "")),
                         ssh_user=f.get("ssh_user") or "",
                         ssh_port=int(f.get("ssh_port") or 0) if
                         (f.get("ssh_port") or "").strip().isdigit() else 0,
                         host_vars=f.get("host_vars") or "",
                         env=f.get("env") or "",
                         label=f.get("label") or "")
    except ansible.Refused as e:
        return RedirectResponse(_group_url(gid, err=str(e)), 303)
    return RedirectResponse(_group_url(gid, msg="host added"), 303)


@app.post("/ansible/host/update")
async def ansible_update_host(request: Request):
    f = await request.form()
    gid = (f.get("gid") or "").strip()
    me = getattr(request.state, "user", None)
    try:
        await run_in_threadpool(ansible.update_host, (f.get("hid") or "").strip(),
                                dict(f), (me or {}).get("email", ""))
    except ansible.Refused as e:
        return RedirectResponse(_group_url(gid, err=str(e)), 303)
    auth.audit(me, "ansible_host_updated", f.get("name") or "",
               f"in group {gid}", _client_ip(request))
    return RedirectResponse(_group_url(gid, msg="host updated"), 303)


@app.post("/ansible/host/paste")
async def ansible_paste_hosts(request: Request):
    """Several hosts at once, into a group that already exists.

    The single row under the table is for one host with its own user or port; this
    is for the twenty addresses somebody has in a list. Both land in the same
    place, and only the create form had the second one — so adding a fleet to an
    existing group meant twenty visits to a one-line form.
    """
    f = await request.form()
    gid = (f.get("gid") or "").strip()
    me = getattr(request.state, "user", None)
    added, skipped = ansible.add_hosts_text(gid, str(f.get("hosts") or ""),
                                            (me or {}).get("email", ""))
    note = f"{added} host(s) added"
    if skipped:
        note += f" · {len(skipped)} skipped: " + "; ".join(skipped[:3])
    return RedirectResponse(
        _group_url(gid, **({"msg": note} if added else {"err": note or
                           "nothing there to add"})), 303)


@app.post("/ansible/host/delete")
async def ansible_delete_host(request: Request):
    f = await request.form()
    ansible.delete_host((f.get("hid") or "").strip())
    return RedirectResponse(_group_url(f.get("gid") or "",
                                       msg="host removed"), 303)


@app.post("/ansible/hosts/delete")
async def ansible_delete_hosts(request: Request):
    """Remove the hosts somebody TICKED, which is what the ticks looked like
    they were for.

    WHY THIS EXISTS. The group page had exactly one selection -- a column of
    ticks -- and its only consumer was the ssh-key dialog. The only control
    labelled delete was "Delete this group". So somebody ticked a few hosts,
    pressed the thing that says delete, and lost the whole group: the software
    did what its button said and not remotely what the page implied. A
    selection with no destructive action of its own, on a page that has a
    destructive action ignoring it, is a trap however carefully the button is
    worded.

    VALIDATED AGAINST THE GROUP, not trusted. The ids arrive from a form, so
    each one is checked to be a host of THIS group before anything is deleted
    -- otherwise this route would delete any host in the install by id, which
    is a worse version of the bug it is fixing.
    """
    f = await request.form()
    gid = (f.get("gid") or "").strip()
    g = ansible.group(gid)
    if not g:
        return RedirectResponse(_group_url(gid, err="that group is gone"), 303)
    mine = {h["id"]: h["name"] for h in ansible.hosts_of(gid)}
    want = [str(x).strip() for x in f.getlist("hid") if str(x).strip()]
    doomed = [h for h in want if h in mine]
    for hid in doomed:
        ansible.delete_host(hid)
    if doomed:
        auth.audit(getattr(request.state, "user", None),
                   "ansible_hosts_removed", g.get("name") or gid,
                   f"{len(doomed)} host(s): "
                   + ", ".join(mine[h] for h in doomed)[:300],
                   _client_ip(request))
    # Says how many, because "host removed" after ticking six is the same
    # silence that started this.
    n = len(doomed)
    return RedirectResponse(_group_url(
        gid, msg=(f"{n} host{'s' if n != 1 else ''} removed" if n
                  else "nothing was selected")), 303)


@app.post("/ansible/host/import")
async def ansible_import_hosts(request: Request):
    """Take hosts out of the server inventory the portal already holds."""
    f = await request.form()
    gid = (f.get("gid") or "").strip()
    ids = [v for v in f.getlist("asset_ids") if v]
    if not ids:
        return RedirectResponse(
            _group_url(gid, err="choose at least one server"), 303)
    added, skipped = ansible.from_inventory(
        gid, ids, (getattr(request.state, "user", None) or {}).get("email", ""))
    note = f"{added} host(s) added from the inventory"
    if skipped:
        note += f" · {len(skipped)} skipped: " + "; ".join(skipped[:3])
    return RedirectResponse(_group_url(gid, msg=note), 303)


@app.post("/ansible/run")
async def ansible_start_run(request: Request):
    """Start a run. The only route that changes anything on a host.

    Answers JSON rather than redirecting: the window that posts this stays open
    and starts following the output, and a navigation here would close it.
    """
    f = await request.form()
    me = getattr(request.state, "user", None)
    why = _may_run(request)
    if why:
        return JSONResponse({"ok": False, "error": why}, 403)
    check = (f.get("check") or "") not in ("", "0", "false")
    try:
        run_id = ansible.start(
            (f.get("pb_id") or "").strip(), (f.get("gid") or "").strip(),
            (me or {}).get("email", ""), check=check,
            limit_to=(f.get("limit") or "").strip(),
            tags=(f.get("tags") or "").strip(),
            extra_vars=(f.get("extra_vars") or "").strip(),
            allow_real=ansible.config()["allow_real"],
            confirm=f.get("confirm") or "")
    except ansible.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    pb = ansible.playbook(f.get("pb_id") or "") or {}
    auth.audit(me, "ansible_check" if check else "ansible_run",
               f"{pb.get('name', '?')} → {f.get('gid')}",
               f"run {run_id}" + (f" limit={f.get('limit')}"
                                  if f.get("limit") else ""),
               _client_ip(request))
    return JSONResponse({"ok": True, "run_id": run_id})


@app.get("/ansible/run/{run_id}.json")
def ansible_run_json(run_id: str, since: int = 0):
    """A run, and whatever it has printed since byte `since`."""
    got = ansible.run(run_id, since=max(0, since))
    if not got:
        return JSONResponse({"error": "no such run"}, 404)
    return JSONResponse(got)


@app.post("/ansible/run/{run_id}/cancel")
def ansible_cancel_run(request: Request, run_id: str):
    why = _may_run(request)
    if why:
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    stopped = ansible.cancel(run_id, (me or {}).get("email", "") or "somebody")
    if stopped:
        auth.audit(me, "ansible_cancelled", run_id, "", _client_ip(request))
    return JSONResponse({"ok": stopped,
                         "error": "" if stopped else "it is no longer running"})


# ── Terraform ──────────────────────────────────────────────────
# Reading the stacks and runs is the `terraform` area (the /terraform prefix,
# governed by the middleware). Running anything — init, plan, apply, destroy —
# is `terraform_apply`, the escalating half checked in the handler, because even
# a plan runs the provider's code with the stack's credential. `allow_apply` is
# the installation switch on top: apply/destroy also need it on and a production
# stack's name typed.
def _tf_back(sec: str = "", **extra) -> str:
    url = "/terraform" + (f"?sec={sec}" if sec else "")
    q = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in extra.items() if v)
    return url + (("&" if "?" in url else "?") + q if q else "")


def _may_apply(request: Request) -> str:
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "terraform_apply"):
        return ("your role may read the Terraform stacks and runs but not run "
                "terraform — that needs “Terraform: apply”")
    return ""


@app.get("/terraform", response_class=HTMLResponse)
def terraform_page(request: Request, sec: str = "", msg: str = "", err: str = "",
                   proj: str = "", reg: str = "", focus: str = ""):
    """The Infrastructure Provisioning plane: recipes, the live VM inventory, the
    hosts overview, the per-host image library, stacks, and the runs against them.
    The page's own region picker (`reg`) filters every tab; "" shows all."""
    cur = sec if sec in ("overview", "instances", "hosts", "images", "stacks", "runs") else "overview"
    region_opts = _region_options()
    if reg not in {r["id"] for r in region_opts}:
        reg = ""

    def _in_region(rgid: str) -> bool:
        return not reg or rgid == reg

    stacks_l = [s for s in terraform.stacks() if _in_region(s.get("rgid", ""))]
    for s in stacks_l:                       # link the post-provision playbook run, if any
        s["arun"] = provision.ansible_run_id(s["id"])
    runs_l = [r for r in terraform.runs(120) if _in_region(r.get("rgid", ""))]
    return templates.TemplateResponse(
        request, "terraform.html",
        ctx(request, sec=cur, msg=msg, err=err, focus_stack=focus,
            stacks=stacks_l, runs=runs_l, reg=reg, region_opts=region_opts,
            region_label=(next((r["name"] for r in region_opts
                                if r["id"] == reg), "All regions")
                          if reg else "All regions"),
            summary=terraform.summary(reg),
            recipes=provision.presets(),
            ansible_playbooks=[{"id": p["id"], "name": p["name"]} for p in ansible.playbooks()],
            may_ansible=(not _may_run(request)),
            clusters=provision.clusters(), os_choices=provision.os_choices(),
            cfg=terraform.config(), tool=terraform.tool(),
            may_apply=not _may_apply(request), why_no_apply=_may_apply(request)))


@app.get("/terraform/stacks/{sid}", response_class=HTMLResponse)
def terraform_stack_page(request: Request, sid: str, msg: str = "", err: str = ""):
    """One stack, in an editor, for viewing/editing an existing stack. Creating a
    hand-written stack was retired in favour of the "Provision a VM" chooser, so
    `new` redirects to the Provisioning page."""
    if sid == "new":
        return RedirectResponse("/terraform", 303)
    st = terraform.stack(sid)
    if not st:
        return RedirectResponse(_tf_back("stacks", err="that stack is gone"), 303)
    return templates.TemplateResponse(
        request, "terraform_stack.html",
        ctx(request, st=st, sid="" if sid == "new" else sid, msg=msg, err=err,
            place_options=_place_options(), env_suggest=pam.ENV_SUGGEST,
            revs=terraform.revisions(sid) if st else [],
            runs=terraform.runs(25, sid) if st else [],
            cfg=terraform.config(), tool=terraform.tool(),
            may_apply=not _may_apply(request), why_no_apply=_may_apply(request)))


@app.post("/terraform/stack/save")
async def terraform_save_stack(request: Request):
    f = await request.form()
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "terraform"):
        return RedirectResponse(_tf_back("stacks", err="not permitted"), 303)
    try:
        sid = await run_in_threadpool(terraform.save_stack,
                                      (f.get("sid") or "").strip(), dict(f),
                                      (me or {}).get("email", ""))
    except terraform.Refused as e:
        back = urllib.parse.quote((f.get("sid") or "new"))
        return RedirectResponse(
            f"/terraform/stacks/{back}?err={urllib.parse.quote(str(e))}", 303)
    auth.audit(me, "tf_stack_saved", f.get("name") or sid, "", _client_ip(request))
    return RedirectResponse(f"/terraform/stacks/{sid}?msg=saved", 303)


@app.post("/terraform/stack/delete")
async def terraform_delete_stack(request: Request):
    f = await request.form()
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "terraform"):
        return RedirectResponse(_tf_back("stacks", err="not permitted"), 303)
    sid = (f.get("sid") or "").strip()
    st = terraform.stack(sid)
    gone = await run_in_threadpool(terraform.delete_stack, sid)
    if gone and st:
        auth.audit(me, "tf_stack_deleted", st.get("name", ""), "",
                   _client_ip(request))
    return RedirectResponse(_tf_back("stacks", msg="stack deleted" if gone
                                     else "that stack is already gone"), 303)


@app.post("/terraform/stack/restore")
async def terraform_restore_stack(request: Request):
    f = await request.form()
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "terraform"):
        return RedirectResponse(_tf_back("stacks", err="not permitted"), 303)
    sid = (f.get("sid") or "").strip()
    body = terraform.revision_body((f.get("rev") or "").strip())
    st = terraform.stack(sid)
    if body is None or not st:
        return RedirectResponse(_tf_back("stacks", err="that revision is gone"), 303)
    fields = {"name": st["name"], "provider": st["provider"], "env": st["env"],
              "is_prod": st["is_prod"], "notes": st.get("notes", ""), "body": body,
              "tfvars": st.get("tfvars", ""), "pid": st.get("pid", ""),
              "rgid": st.get("rgid", "")}
    try:
        await run_in_threadpool(terraform.save_stack, sid, fields,
                                (me or {}).get("email", ""))
    except terraform.Refused as e:
        return RedirectResponse(f"/terraform/stacks/{sid}?err="
                                f"{urllib.parse.quote(str(e))}", 303)
    return RedirectResponse(f"/terraform/stacks/{sid}?msg=revision restored", 303)


@app.post("/terraform/run")
async def terraform_run(request: Request):
    """Trigger a run — JSON, so the run window stays open. The only route that
    can change infrastructure."""
    f = await request.form()
    me = getattr(request.state, "user", None)
    if (why := _may_apply(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    action = (f.get("action") or "").strip()
    try:
        run_id = terraform.start(
            (f.get("sid") or "").strip(), action, (me or {}).get("email", ""),
            allow_apply=terraform.config()["allow_apply"],
            confirm=f.get("confirm") or "")
    except terraform.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    sid = (f.get("sid") or "").strip()
    st = terraform.stack(sid) or {}
    auth.audit(me, f"tf_{action}", st.get("name", "?"), f"run {run_id}",
               _client_ip(request))
    # A provisioned stack that carries a post-boot playbook runs it SERVER-SIDE:
    # arm a background worker off this apply so it waits for the VMs on SSH and
    # runs the playbook even if the wizard is closed. The client only watches it.
    if action == "apply" and provision.ansible_for(sid):
        provision.arm_post_ansible(sid, run_id, (me or {}).get("email", ""))
    return JSONResponse({"ok": True, "run_id": run_id})


@app.get("/terraform/run/{run_id}.json")
def terraform_run_json(run_id: str, since: int = 0):
    """A run, and whatever it has printed since byte `since` — the poll endpoint."""
    got = terraform.run(run_id, since=max(0, since))
    if not got:
        return JSONResponse({"error": "no such run"}, 404)
    return JSONResponse(got)


@app.post("/terraform/run/{run_id}/cancel")
def terraform_cancel_run(request: Request, run_id: str):
    if (why := _may_apply(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    stopped = terraform.cancel(run_id, (me or {}).get("email", "") or "somebody")
    if stopped:
        auth.audit(me, "tf_cancelled", run_id, "", _client_ip(request))
    return JSONResponse({"ok": stopped,
                         "error": "" if stopped else "it is no longer running"})


@app.post("/terraform/run/delete")
async def terraform_delete_run(request: Request):
    f = await request.form()
    if (why := _may_apply(request)):
        return RedirectResponse(_tf_back("runs", err=why), 303)
    try:
        gone = await run_in_threadpool(terraform.delete_run,
                                       (f.get("rid") or "").strip())
    except terraform.Refused as e:
        return RedirectResponse(_tf_back("runs", err=str(e)), 303)
    return RedirectResponse(_tf_back("runs", msg="run deleted" if gone
                                     else "that run is gone"), 303)


@app.post("/terraform/runs/clear")
async def terraform_clear_runs(request: Request):
    f = await request.form()
    if (why := _may_apply(request)):
        return RedirectResponse(_tf_back("runs", err=why), 303)
    n = await run_in_threadpool(terraform.clear_runs, (f.get("which") or "finished"))
    return RedirectResponse(_tf_back("runs", msg=f"{n} run(s) cleared" if n
                                     else "nothing to clear"), 303)


@app.get("/settings/terraform", response_class=HTMLResponse)
def settings_terraform(request: Request, msg: str = ""):
    return templates.TemplateResponse(
        request, "set_terraform.html",
        ctx(request, cfg=terraform.config(), tool=terraform.tool(), msg=msg))


@app.post("/settings/terraform")
async def settings_terraform_save(request: Request):
    f = await request.form()
    me = getattr(request.state, "user", None)
    was = terraform.config()["allow_apply"]
    now = bool(f.get("allow_apply"))
    terraform.save_config(allow_apply=now, parallelism=f.get("parallelism"))
    if was != now:
        auth.audit(me, "tf_apply_" + ("enabled" if now else "disabled"),
                   "this installation", "", _client_ip(request))
    return RedirectResponse("/settings/terraform?msg=saved", 303)


# ── Provision (guided VM / cluster creation on the Terraform engine) ─
# The wizard collects a spec (OS, destination nodes, resources, static network)
# and GENERATES a Terraform stack from it — nothing here provisions directly, so
# creating is the `terraform` area (writing a stack); running the stack it makes
# still needs `terraform_apply` + the installation switch, same as any stack.
def _may_provision(request: Request) -> str:
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "terraform"):
        return ("your role may not create Terraform stacks — that needs the "
                "“Terraform” area")
    return ""


def _provision_discover(connection: str) -> dict:
    # nodes carry their live CPU / RAM / disk so the wizard can show what each has
    # free (helping pick where a VM lands). datastores and bridges are
    # cluster-uniform in practice, so read them for the first node only — one
    # round-trip, not one per node (which times out).
    with provision.client_for(connection) as px:
        version = px.version()
        nodes = px.nodes_detail()
        if nodes:
            nodes[0]["storages"] = px.storages(nodes[0]["node"])
            nodes[0]["bridges"] = px.bridges(nodes[0]["node"])
    return {"version": version, "nodes": nodes}


@app.get("/provision/discover")
async def provision_discover(request: Request, connection: str = ""):
    """Live read from Proxmox: nodes, their datastores and bridges — so the
    wizard offers real choices instead of free-text."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    try:
        data = await run_in_threadpool(_provision_discover, connection)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)})
    return JSONResponse({"ok": True, **data})


@app.get("/provision/inventory")
async def provision_inventory(request: Request, connection: str = ""):
    """Every VM the Proxmox connection(s) report — the EC2-style fleet list. Loaded
    by the Instances tab after the page paints, so a slow/unreachable Proxmox never
    blocks the hub. Read-only."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    try:
        data = await run_in_threadpool(provision.inventory, connection)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)})
    return JSONResponse({"ok": True, **data})


@app.get("/provision/hosts")
async def provision_hosts(request: Request, connection: str = ""):
    """Every Proxmox node with its live CPU / RAM / disk and VM count — the Hosts
    overview. Loaded after paint; read-only; cluster or standalone."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    try:
        data = await run_in_threadpool(provision.hosts, connection)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)})
    return JSONResponse({"ok": True, **data})


@app.get("/provision/host/detail")
async def provision_host_detail(request: Request, connection: str = "", node: str = ""):
    """One node's VMs + all its datastores — loaded when a host is expanded."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    if not (connection and node):
        return JSONResponse({"ok": False, "error": "connection and node are required"}, 400)
    try:
        data = await run_in_threadpool(provision.host_detail, connection, node)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)})
    return JSONResponse({"ok": True, **data})


@app.post("/provision/host/remove")
async def provision_host_remove(request: Request):
    """Remove a Proxmox connection (cluster/host) from the portal. Deletes the
    connection stack only — the Proxmox is untouched. Confirmed in the UI, audited."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    try:
        spec = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    sid = (spec.get("connection") or "").strip()
    st = terraform.stack(sid) or {}
    try:
        gone = await run_in_threadpool(provision.remove_connection, sid)
    except provision.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    if gone:
        auth.audit(me, "host_remove", st.get("name", sid), f"connection {sid}", _client_ip(request))
    return JSONResponse({"ok": bool(gone)})


@app.get("/provision/cluster/download")
async def provision_cluster_download(request: Request, sid: str = "", which: str = ""):
    """Download a Talos cluster's kubeconfig / talosconfig (a terraform output) as a
    file, once the cluster has been applied."""
    from fastapi.responses import PlainTextResponse
    if (why := _may_apply(request)):
        return PlainTextResponse(why, status_code=403)
    if which not in ("kubeconfig", "talosconfig"):
        return PlainTextResponse("unknown file", status_code=400)
    outs = await run_in_threadpool(terraform.read_outputs, sid)
    val = outs.get(which)
    if not val:
        return PlainTextResponse(f"{which} is not available yet — apply the cluster first",
                                 status_code=404)
    st = terraform.stack(sid) or {}
    me = getattr(request.state, "user", None)
    auth.audit(me, "cluster_download", st.get("name", sid), which, _client_ip(request))
    fname = f"{st.get('name', 'cluster')}-{which}"
    return PlainTextResponse(str(val), headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.post("/provision/ansible/run")
async def provision_ansible_run(request: Request, sid: str = ""):
    """Manually (re)arm the post-provision playbook — the "run it now / retry"
    button for a stack whose auto-run failed or was never armed. The apply's own
    trigger arms it automatically on a normal launch; this is the fallback. It is
    idempotent (a run already in flight is left alone) and returns immediately —
    the run happens SERVER-SIDE and its progress is read from …/ansible/status.
    Gated by `ansible_run`."""
    if (why := _may_run(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    cfg = provision.ansible_for(sid)
    if not cfg or not cfg.get("private_key"):
        return JSONResponse({"ok": False, "error": "no Ansible playbook is attached to this stack"}, 404)
    me = getattr(request.state, "user", None)
    armed = provision.arm_post_ansible(sid, "", (me or {}).get("email", ""))
    return JSONResponse({"ok": True, "armed": armed, **provision.post_ansible_status(sid)})


@app.get("/provision/ansible/status")
async def provision_ansible_status(request: Request, sid: str = ""):
    """Where the background post-provision playbook is up to — the wizard and the
    stack page poll this. Read-only, so it rides the `terraform` (read) gate."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    if not provision.ansible_for(sid):
        return JSONResponse({"ok": True, "attached": False})
    return JSONResponse({"ok": True, "attached": True, **provision.post_ansible_status(sid)})


@app.get("/provision/console", response_class=HTMLResponse)
def provision_console_page(request: Request, connection: str = "", node: str = "",
                          vmid: str = "", name: str = ""):
    """The in-portal VNC console — a standalone noVNC page opened in its own window
    from the Instances actions. It fetches a session, then relays through the WS."""
    if (why := _may_apply(request)):
        return HTMLResponse(f"<p style='font:14px sans-serif;padding:2rem;color:#c33'>{why}</p>", 403)
    return templates.TemplateResponse(
        request, "console.html",
        {"request": request, "connection": connection, "node": node,
         "vmid": vmid, "name": name or f"vm-{vmid}"})


@app.get("/provision/vm/console-open")
async def provision_console_open(request: Request, connection: str = "",
                                 node: str = "", vmid: str = ""):
    """Mint a one-time console session (calls Proxmox vncproxy server-side)."""
    if (why := _may_apply(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    if not (connection and node and vmid):
        return JSONResponse({"ok": False, "error": "connection, node and vmid are required"}, 400)
    me = getattr(request.state, "user", None)
    try:
        res = await run_in_threadpool(provision.console_open, connection, node, vmid)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)})
    auth.audit(me, "vm_console", f"{node}/{vmid}", f"connection {connection}", _client_ip(request))
    return JSONResponse({"ok": True, **res})


@app.websocket("/provision/vm/console.ws")
async def provision_console_ws(ws: WebSocket, session: str = ""):
    """Relay the RFB stream between the browser's noVNC and Proxmox's vncwebsocket.
    The socket is authenticated here (middleware does not run for WebSockets) and
    the console session is single-use."""
    user = _ws_user(ws)
    if not user or not rbac.may_area(user, "terraform_apply"):
        await ws.close(code=4403)
        return
    info = await run_in_threadpool(provision.console_take, session)
    if not info:
        await ws.close(code=4404)
        return
    try:
        up = await run_in_threadpool(provision.console_upstream, info)
    except (provision.Refused, provision.ProxmoxError):
        await ws.close(code=1011)
        return
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    if up["insecure"]:
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
    await ws.accept()
    proxmox_ws = None
    try:
        proxmox_ws = await websockets.connect(
            up["url"], additional_headers=up["headers"], subprotocols=["binary"],
            ssl=ctx, max_size=None, open_timeout=12)

        async def to_proxmox():
            try:
                while True:
                    await proxmox_ws.send(await ws.receive_bytes())
            except (WebSocketDisconnect, RuntimeError, KeyError):
                pass

        async def to_browser():
            try:
                async for msg in proxmox_ws:
                    if isinstance(msg, (bytes, bytearray)):
                        await ws.send_bytes(bytes(msg))
                    else:
                        await ws.send_text(msg)
            except Exception:
                pass

        t1 = asyncio.create_task(to_proxmox())
        t2 = asyncio.create_task(to_browser())
        _done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
    except (WebSocketDisconnect, OSError, websockets.WebSocketException, asyncio.TimeoutError):
        pass
    finally:
        if proxmox_ws is not None:
            with contextlib.suppress(Exception):
                await proxmox_ws.close()
        with contextlib.suppress(Exception):
            await ws.close()


@app.post("/provision/vm/action")
async def provision_vm_action(request: Request):
    """Start / shutdown / reboot / stop a VM. This changes real infrastructure, so
    it needs the escalating permission AND the installation's apply switch, and it
    is audited. The UI confirms it (and types the name for a stop)."""
    if (why := _may_apply(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    if not terraform.config()["allow_apply"]:
        return JSONResponse({"ok": False, "error": "power actions are switched off"
                             " — an administrator turns them on in Settings"}, 400)
    me = getattr(request.state, "user", None)
    try:
        spec = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    conn = (spec.get("connection") or "").strip()
    node = (spec.get("node") or "").strip()
    vmid, action = spec.get("vmid"), (spec.get("action") or "").strip()
    if not (conn and node and vmid):
        return JSONResponse({"ok": False, "error": "connection, node and vmid are required"}, 400)
    try:
        upid = await run_in_threadpool(provision.vm_action, conn, node, vmid, action)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    auth.audit(me, f"vm_{action}", f"{node}/{vmid}", f"connection {conn}",
               _client_ip(request))
    return JSONResponse({"ok": True, "task": upid})


@app.get("/provision/vm/detail")
async def provision_vm_detail(request: Request, connection: str = "", node: str = "",
                              vmid: str = ""):
    """A VM's full hardware config + live status, read live from Proxmox — the
    detail/edit modal. Read-only, so it rides the same gate as the inventory."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    if not (connection and node and vmid):
        return JSONResponse({"ok": False, "error": "connection, node and vmid are required"}, 400)
    try:
        detail = await run_in_threadpool(provision.vm_detail, connection, node, vmid)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    return JSONResponse({"ok": True, "detail": detail})


@app.post("/provision/vm/edit")
async def provision_vm_edit(request: Request):
    """Change a VM's CPU / memory / name / tags / description. Changes real
    infrastructure, so — exactly like a power action — it needs the escalating
    permission AND the installation's apply switch, and it is audited."""
    if (why := _may_apply(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    if not terraform.config()["allow_apply"]:
        return JSONResponse({"ok": False, "error": "VM edits are switched off — an "
                             "administrator turns them on in Settings"}, 400)
    me = getattr(request.state, "user", None)
    try:
        spec = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    conn = (spec.get("connection") or "").strip()
    node = (spec.get("node") or "").strip()
    vmid, changes = spec.get("vmid"), spec.get("changes")
    if not (conn and node and vmid):
        return JSONResponse({"ok": False, "error": "connection, node and vmid are required"}, 400)
    if not isinstance(changes, dict) or not changes:
        return JSONResponse({"ok": False, "error": "no changes provided"}, 400)
    try:
        res = await run_in_threadpool(provision.vm_edit, conn, node, vmid, changes)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    auth.audit(me, "vm_edit", f"{node}/{vmid}",
               "changed " + ", ".join(res["changed"]) + f" · connection {conn}",
               _client_ip(request))
    return JSONResponse({"ok": True, **res})


@app.get("/provision/iso")
async def provision_iso(request: Request, connection: str = ""):
    """The ISO / import images on every node of a cluster — the Images tab."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    if not connection:
        return JSONResponse({"ok": False, "error": "pick a cluster"}, 400)
    try:
        hosts = await run_in_threadpool(provision.host_images, connection)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)})
    return JSONResponse({"ok": True, "hosts": hosts})


@app.post("/provision/iso/delete")
async def provision_iso_delete(request: Request):
    """Delete one ISO / image from a node's datastore. Destructive; gated on the
    provisioning area, confirmed in the UI, audited."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    try:
        spec = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    conn, node = (spec.get("connection") or "").strip(), (spec.get("node") or "").strip()
    storage, volid = (spec.get("storage") or "local").strip(), (spec.get("volid") or "").strip()
    if not (conn and node and volid):
        return JSONResponse({"ok": False, "error": "connection, node and image are required"}, 400)
    try:
        await run_in_threadpool(provision.delete_iso, conn, node, storage, volid)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    auth.audit(me, "iso_delete", f"{node}:{storage}", volid, _client_ip(request))
    return JSONResponse({"ok": True})


@app.post("/provision/host/test")
async def provision_host_test(request: Request):
    """Try entered Proxmox credentials without saving — the add-host wizard's Test.
    The user supplies their own credentials; the portal never fills them in."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    try:
        spec = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    try:
        res = await run_in_threadpool(provision.test_connection, spec)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)})
    return JSONResponse({"ok": True, **res})


@app.post("/provision/host/add")
async def provision_host_add(request: Request):
    """Register a Proxmox host/cluster as a connection (a sealed-credential stack).
    The credential is sealed by save_stack and never returned to a page."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    try:
        spec = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    try:
        sid = await run_in_threadpool(provision.add_host, spec, (me or {}).get("email", ""))
    except provision.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    st = terraform.stack(sid) or {}
    auth.audit(me, "host_add", st.get("name", "?"), f"connection {sid}", _client_ip(request))
    return JSONResponse({"ok": True, "sid": sid, "name": st.get("name", "")})


@app.get("/provision/host/get")
async def provision_host_get(request: Request, sid: str = ""):
    """Non-secret fields of a Proxmox connection, to pre-fill the edit form. The
    token/password are NEVER returned — only which auth kind is stored."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    try:
        data = await run_in_threadpool(provision.host_get, (sid or "").strip())
    except provision.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    return JSONResponse({"ok": True, **data})


@app.post("/provision/host/edit")
async def provision_host_edit(request: Request):
    """Update a Proxmox connection — endpoint, placement, and (only if a new one is
    supplied) the credential. Left blank, the stored credential is kept. Sealed by
    save_stack; never returned to a page. Audited."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    try:
        spec = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    sid = (spec.get("sid") or "").strip()
    try:
        sid = await run_in_threadpool(provision.edit_host, sid, spec, (me or {}).get("email", ""))
    except provision.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    st = terraform.stack(sid) or {}
    auth.audit(me, "host_edit", st.get("name", "?"), f"connection {sid}", _client_ip(request))
    return JSONResponse({"ok": True, "sid": sid, "name": st.get("name", "")})


@app.post("/provision/host/add-many")
async def provision_host_add_many(request: Request):
    """Register several standalone Proxmox hosts in one shot (the Standalone option
    of the add-host wizard). Each is its own sealed-credential connection; partial
    success is reported per host so one bad credential does not lose the batch."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    try:
        body = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    specs = body.get("hosts") if isinstance(body, dict) else None
    if not isinstance(specs, list) or not specs:
        return JSONResponse({"ok": False, "error": "no hosts to add"}, 400)
    results = await run_in_threadpool(provision.add_hosts, specs, (me or {}).get("email", ""))
    for r in results:
        if r.get("ok"):
            auth.audit(me, "host_edit" if r.get("edited") else "host_add",
                       r.get("name", "?"), f"connection {r.get('sid')}", _client_ip(request))
    return JSONResponse({"ok": True, "results": results})


@app.post("/provision/iso/upload")
async def provision_iso_upload(request: Request, file: UploadFile = File(...),
                               connection: str = Form(...), node: str = Form(...),
                               storage: str = Form("local"), content: str = Form("iso")):
    """Stream an ISO from the user's device, through the portal, onto a node — the
    nodes are air-gapped, so the portal (which has the file) is the courier. Large
    ISOs are a slow transfer; the file is spooled to a temp path, then pushed."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    tmp = tempfile.mkdtemp(prefix="iso-up-")
    dest = os.path.join(tmp, os.path.basename(file.filename or "upload.iso"))
    try:
        with open(dest, "wb") as fh:
            while chunk := await file.read(1024 * 1024):
                fh.write(chunk)
        got = await run_in_threadpool(provision.upload_iso, connection, node,
                                      storage, file.filename or "upload.iso", dest, content)
    except (provision.Refused, provision.ProxmoxError, OSError) as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    auth.audit(me, "iso_upload", f"{node}:{storage}/{content}", file.filename or "",
               _client_ip(request))
    return JSONResponse({"ok": True, "volid": got})


@app.get("/provision/image")
async def provision_image(request: Request, connection: str = "", node: str = "",
                          storage: str = "", os: str = "", ver: str = ""):
    """Is the chosen OS image already in the datastore? The 'check image' button."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    res = await run_in_threadpool(provision.image_status, connection, node,
                                  storage, os, ver)
    return JSONResponse(res)


@app.post("/provision/create")
async def provision_create(request: Request):
    """Generate a stack from the wizard spec and persist it (reusing the
    connection's sealed credential). Returns the new stack id to open."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    try:
        spec = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    try:
        sid = await run_in_threadpool(provision.create, spec,
                                      (me or {}).get("email", ""))
    except (provision.Refused, provision.ProxmoxError) as e:
        # ProxmoxError (e.g. an OEMDRV upload rejected) is unrelated to Refused, so
        # it used to escape the route as an HTML 500 — which the JS `.json()` then
        # read as "Unexpected token '<'". A wizard POST must always answer JSON.
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    except Exception as e:                                # noqa: BLE001
        import logging
        logging.getLogger("uvicorn.error").exception("provision.create failed")
        return JSONResponse({"ok": False, "error": f"could not generate the stack: {e}"}, 500)
    st = terraform.stack(sid) or {}
    auth.audit(me, "tf_provision", st.get("name", "?"),
               f"generated stack {sid}", _client_ip(request))
    return JSONResponse({"ok": True, "sid": sid, "name": st.get("name", "")})


@app.post("/provision/stage")
async def provision_stage(request: Request):
    """EnvMap fetches the OS image (it has internet) and pushes it onto the
    node(s) over 8006 — so air-gapped nodes never reach out. Returns a job id."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    try:
        spec = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    conn = (spec.get("connection") or "").strip()
    nodes = [n for n in (spec.get("nodes") or []) if n]
    os_key = (spec.get("os") or "").strip()
    if not (conn and nodes and os_key):
        return JSONResponse({"ok": False, "error": "need a connection, an image and node(s)"}, 400)
    try:
        job = await run_in_threadpool(
            provision.stage_start, conn, nodes, os_key, (spec.get("ver") or "").strip(),
            (spec.get("image_datastore") or "local").strip(), (me or {}).get("email", ""))
    except provision.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    auth.audit(me, "tf_stage_image", os_key,
               f"{len(nodes)} node(s) via {conn}", _client_ip(request))
    return JSONResponse({"ok": True, "job": job})


@app.get("/provision/stage/{job}.json")
def provision_stage_status(job: str):
    st = provision.stage_status(job)
    if not st:
        return JSONResponse({"error": "no such job"}, 404)
    return JSONResponse(st)


@app.get("/provision/images")
async def provision_images(request: Request, connection: str = "", node: str = "",
                           storage: str = "local"):
    """Existing images already on a node's datastore — the wizard's dropdown."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    if not (connection and node):
        return JSONResponse({"ok": False, "error": "need a connection and a node"}, 400)
    try:
        imgs = await run_in_threadpool(provision.datastore_images, connection, node, storage)
    except (provision.Refused, provision.ProxmoxError) as e:
        return JSONResponse({"ok": False, "error": str(e)})
    return JSONResponse({"ok": True, "images": imgs})


@app.get("/provision/download")
def provision_download(request: Request, os: str = "", ver: str = ""):
    """Redirect the browser to the OS image's public URL so the user can download
    it to their own machine — the portal stores nothing."""
    if (why := _may_provision(request)):
        return RedirectResponse("/terraform", 303)
    url = provision.image_source_url(os, ver)
    if not url:
        return JSONResponse({"error": "unknown image"}, 404)
    return RedirectResponse(url, 307)


@app.post("/provision/stage-probe")
async def provision_stage_probe(request: Request):
    """Verify the 8006 upload API accepts a disk-image `.img` on this cluster —
    a tiny, self-cleaning upload/list/delete. No large transfer."""
    if (why := _may_provision(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    try:
        spec = await request.json()
    except (ValueError, TypeError):
        return JSONResponse({"ok": False, "error": "malformed request"}, 400)
    conn = (spec.get("connection") or "").strip()
    node = (spec.get("node") or "").strip()
    storage = (spec.get("storage") or "local").strip()
    if not (conn and node):
        return JSONResponse({"ok": False, "error": "need a connection and a node"}, 400)
    res = await run_in_threadpool(provision.stage_probe, conn, node, storage)
    return JSONResponse(res)


# ── Privileged Access (PAM) ────────────────────────────────────
# Reading the catalogue and the recordings is the `pam` area (the /pam prefix,
# governed by the middleware). Opening a live session, or deleting/killing one,
# is `pam_connect` — the escalating half, checked in the handler because its
# prefix is empty. `allow_connect` is the installation switch on top of the
# permission: a portal can hold a catalogue nobody can dial until an admin turns
# connections on, the same posture as Ansible's real-run switch.
def _may_connect(request: Request) -> str:
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "pam_connect"):
        return ("your role may read the access catalogue but not open a live "
                "session — that needs “Privileged Access: connect”")
    return ""


def _ws_pam(ws: WebSocket):
    """The person behind a PAM socket if they may open a live session."""
    u = current_user(ws)
    return u if u and rbac.may_area(u, "pam_connect") else None


def _may_target(user, tid: str) -> bool:
    """Whether this person may open a live session on this specific target —
    the per-device half of Privileged Access, on top of the pam_connect area."""
    return rbac.may_target(user, tid, "pam_connect")


def _pam_session_scoped(request: Request, sid: str, area: str = "pam"):
    """(row, ok): the session, and whether the requester may see it (area='pam')
    or delete it (area='pam_connect'). A recording is scoped to the target it was
    of, so App A's recordings are reached only by someone granted App A."""
    row = pam.session(sid)
    if not row:
        return None, False
    me = getattr(request.state, "user", None)
    return row, rbac.may_target(me, row.get("target_id", ""), area)


def _pam_back(sec: str = "targets", **extra) -> str:
    q = "&".join(f"{k}={urllib.parse.quote(str(v))}"
                 for k, v in extra.items() if v)
    return f"/pam?sec={sec}" + (f"&{q}" if q else "")


PAM_TABS = ("targets", "sessions", "active")


@app.get("/pam", response_class=HTMLResponse)
def pam_page(request: Request, sec: str = "", msg: str = "", err: str = "",
             proj: str = "", reg: str = "", protocol: str = "", env: str = "",
             sess_who: str = "", focus: str = ""):
    """The access plane: the target catalogue, the recordings, the live sessions."""
    cur = sec if sec in PAM_TABS else "targets"
    projs = store.projects()
    if proj not in projs:
        proj, reg = "", ""
    elif reg and reg not in (projs[proj].get("regions") or {}):
        reg = ""
    if protocol not in pam.PROTOCOLS:
        protocol = ""
    env = pam.env_norm(env)
    me = getattr(request.state, "user", None)
    # Per-device visibility: a role can be scoped to particular targets, and
    # then only those are seen. None (an unscoped role, or an admin) is every
    # target. The catalogue count on the tiles follows the same scope.
    vis = rbac.visible_targets(me, "pam")
    keep = (lambda t: True) if vis is None else (lambda t: t["id"] in vis)
    targets_l = [t for t in pam.targets(proj, reg, protocol, env) if keep(t)]
    summ = pam.summary()
    if vis is not None:
        allv = [t for t in pam.targets() if keep(t)]
        summ = {**summ, "targets": len(allv),
                "live": sum(1 for t in allv
                            if t["protocol"] in ("ssh", "rdp", "vnc"))}
    on_sessions = cur == "sessions"
    # Recordings follow the same per-device scope as the catalogue: a person
    # granted App A sees App A's sessions and no others.
    sessions_l = (pam.sessions(proj, reg, sess_who, visible=vis)
                  if on_sessions else [])
    return templates.TemplateResponse(
        request, "pam.html",
        ctx(request, sec=cur, msg=msg, err=err, focus_target=focus,
            targets=targets_l, sessions=sessions_l,
            # ALWAYS, not only on the Active tab. It used to be built only for
            # that tab, and the tab badge and the "live now" tile both read
            # `active|length` — so every other tab reported ZERO live sessions
            # while sessions were running, which is the clickable-tiles rule
            # broken in the way that matters most (a tile saying nothing is
            # happening). It costs nothing to be right: _active is an in-memory
            # dict in this worker, not a query.
            active=pam.active_sessions(visible=vis),
            sess_stats=(pam.sessions_stats(proj, reg, sess_who, visible=vis)
                        if on_sessions else None),
            sess_facets=(pam.session_facets(proj, reg, visible=vis)
                         if on_sessions else {"users": [], "protocols": []}),
            tgt_facets=pam.target_facets(),
            proto_meta=pam.PROTOCOLS, env_meta=pam.ENV_META,
            proj=proj, reg=reg, protocol=protocol, env=env, sess_who=sess_who,
            place_options=_place_options(),
            summary=summ, cfg=pam.config(),
            guac_ok=pam.guacd_reachable(),
            guacd_why=pam.guacd_why(),
            # Computed ONCE for the page, not per row: it walks the projects
            # and asks whether the browser cluster is usable, and the answer
            # is the same for every web row in the catalogue.
            web_why=webseat.why_unavailable(pam.config()),
            may_connect=not _may_connect(request),
            # The delete/clear controls follow the SAME rule the handlers
            # enforce, or the page offers a button that is refused on submit.
            may_pam_full=rbac.may_pam_full(getattr(request.state, "user", None)),
            why_no_connect=_may_connect(request)))


@app.get("/pam/targets/{tid}", response_class=HTMLResponse)
def pam_target_page(request: Request, tid: str = "", msg: str = "",
                    err: str = ""):
    """Add or edit one target — `/pam/targets/new` is this page, empty. Editing
    never shows the stored secret."""
    if tid in ("", "new"):
        t, tid = None, ""
    else:
        t = pam.target(tid)
        if not t:
            return RedirectResponse(_pam_back("targets",
                                              err="that target is gone"), 303)
    return templates.TemplateResponse(
        request, "pam_target.html",
        ctx(request, t=t, tid=tid, msg=msg, err=err,
            proto_meta=pam.PROTOCOLS, place_options=_place_options(),
            env_suggest=pam.ENV_SUGGEST,
            may_connect=not _may_connect(request)))


@app.post("/pam/target/save")
async def pam_save_target(request: Request):
    f = await request.form()
    if not rbac.may_area(getattr(request.state, "user", None), "pam"):
        return RedirectResponse(_pam_back("targets", err="not permitted"), 303)
    me = getattr(request.state, "user", None)
    try:
        tid = await run_in_threadpool(
            pam.save_target, str(f.get("tid") or ""),
            {k: str(v) for k, v in f.items()}, (me or {}).get("email", ""))
    except pam.Refused as e:
        return RedirectResponse(f"/pam/targets/{f.get('tid') or 'new'}"
                                f"?err={urllib.parse.quote(str(e))}", 303)
    auth.audit(me, "pam_target_saved", f.get("name") or tid,
               str(f.get("protocol") or ""), _client_ip(request))
    return RedirectResponse(_pam_back("targets", msg="target saved",
                                      focus=tid), 303)


@app.post("/pam/target/describe")
async def pam_describe_target(request: Request):
    """Set the hostname and the label of an inventory host, from the catalogue.

    WHY THIS EXISTS AND WHY IT IS ONLY TWO FIELDS. An Ansible inventory host is
    read-only in Privileged Access, because its address, port, user and
    credential are the group's business -- changing them here would move what a
    playbook runs against. But the catalogue is exactly where somebody sits
    looking at a column of bare IP addresses trying to work out which machine
    each one is, and the two fields that answer that question -- the machine's
    own name and a label -- change nothing about how anything connects.

    Written back to the INVENTORY ROW, so the label typed here is the label the
    Ansible page shows. One row, no second copy to disagree.
    """
    if (why := _may_connect(request)):
        return RedirectResponse(_pam_back("targets", err=why), 303)
    f = await request.form()
    tid = str(f.get("tid") or "").strip()
    me = getattr(request.state, "user", None)
    if not _may_target(me, tid):
        return RedirectResponse(_pam_back(
            "targets", err="your roles do not include this target"), 303)
    inv = pam.inventory_of(tid)
    if not inv:
        return RedirectResponse(_pam_back(
            "targets", err="that is not an inventory host — a target entered "
                           "here is edited on its own page"), 303)
    try:
        got = await run_in_threadpool(
            ansible.describe_host, tid, str(f.get("hostname") or ""),
            str(f.get("label") or ""), (me or {}).get("email", ""))
    except ansible.Refused as e:
        return RedirectResponse(_pam_back("targets", err=str(e)), 303)
    auth.audit(me, "pam_target_described", got.get("name") or tid,
               f"hostname={got.get('hostname') or '—'} · "
               f"label={got.get('label') or '—'}", _client_ip(request))
    return RedirectResponse(_pam_back(
        "targets", msg=f"{got.get('name') or tid} described"), 303)


@app.post("/pam/target/delete")
async def pam_delete_target(request: Request):
    f = await request.form()
    if not rbac.may_area(getattr(request.state, "user", None), "pam"):
        return RedirectResponse(_pam_back("targets", err="not permitted"), 303)
    me = getattr(request.state, "user", None)
    tid = str(f.get("tid") or "")
    t = pam.target(tid)
    gone = await run_in_threadpool(pam.delete_target, tid)
    if gone and t:
        auth.audit(me, "pam_target_deleted", t.get("name") or tid, "",
                   _client_ip(request))
    return RedirectResponse(_pam_back("targets", msg="target deleted" if gone
                                      else "that target is gone"), 303)


@app.get("/pam/targets.json")
def pam_targets_json(request: Request):
    """The SSH targets this person may open, for the terminal's + picker. Only
    what they may connect to, filtered the same way the catalogue is."""
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "pam_connect"):
        return JSONResponse([])
    out = [{"id": t["id"], "name": t["name"], "address": t["address"],
            "is_prod": bool(t["is_prod"]), "source": t.get("source", "pam"),
            "project": t.get("project_name", "")}
           for t in pam.targets(protocol="ssh") if _may_target(me, t["id"])]
    return JSONResponse(out)


def _pam_opened_detail(just: dict) -> str:
    """The audit line for a session that just opened — the three-part
    justification folded in when one was given."""
    if just:
        return (f"session opened — {just['summary']} "
                f"[{just['session_time']}] {just['ticket']}")
    return "session opened"


def _pam_preconnect(request, t, action, confirm, ticket, stime, summary,
                    bare: bool = False):
    """The name-and-justification gate shared by the terminal and console pages.
    Returns a rendered confirm page when something is still needed, else None.
    When a reason is required it demands all three parts — ticket URL, session
    time and summary — validated by pam.justification()."""
    need_name = bool(t.get("is_prod")) and confirm != t["name"]
    need_reason = (pam.reason_required(t.get("is_prod"))
                   and pam.justification(ticket, stime, summary) is None)
    if need_name or need_reason:
        return templates.TemplateResponse(
            request, "pam_confirm.html",
            ctx(request, t=t, action=action, need_name=need_name,
                need_reason=need_reason, confirm=confirm, ticket=ticket,
                stime=stime, summary=summary, bare=bare,
                session_times=pam.SESSION_TIMES,
                # THE GATE IS PART OF THE WINDOW. It comes first, so in a
                # console opened as its own window it is the FIRST thing drawn
                # -- and drawn with the portal's sidebar and top bar around it
                # in a window sized for a session, which is both cramped and a
                # different-looking product from the page that follows it.
                bad=bool(confirm) and confirm != t["name"] and t.get("is_prod")))
    return None


@app.get("/pam/targets/{tid}/terminal", response_class=HTMLResponse)
def pam_terminal(request: Request, tid: str, confirm: str = "", ticket: str = "",
                 stime: str = "", summary: str = ""):
    """An SSH session on one target — the page; the socket does the work."""
    if (why := _may_connect(request)):
        return RedirectResponse(_pam_back("targets", err=why), 303)
    t = pam.target(tid)
    if not t or t.get("protocol") != "ssh":
        return RedirectResponse(_pam_back("targets",
                                          err="that is not an SSH target"), 303)
    if not _may_target(getattr(request.state, "user", None), tid):
        return RedirectResponse(_pam_back(
            "targets", err="your roles do not include this target"), 303)
    if not pam.config()["allow_connect"]:
        return RedirectResponse(_pam_back(
            "targets", err="live connections are switched off — an administrator "
            "turns them on in Settings → Privileged Access"), 303)
    if (gate := _pam_preconnect(request, t, "terminal", confirm, ticket, stime,
                                summary)):
        return gate
    return templates.TemplateResponse(
        request, "pam_terminal.html",
        ctx(request, t=t, confirm=confirm, ticket=ticket, stime=stime,
            summary=summary, reason_mode=pam.config()["require_reason"]))


@app.websocket("/pam/ssh.ws")
async def pam_ssh_socket(ws: WebSocket, tid: str = "", rows: int = 24,
                         cols: int = 100):
    """An interactive SSH session on a target, the credential brokered and the
    session recorded — the PAM sibling of the Ansible host terminal."""
    await ws.accept()
    me = _ws_pam(ws)
    meta = pam.ssh_meta(tid)

    async def refuse(text: str) -> None:
        await ws.send_text(f"\r\n\x1b[31m{text}\x1b[0m\r\n")
        await ws.close(code=4001, reason=text[:110])

    if not me:
        await refuse("you do not have Privileged Access: connect"); return
    if not pam.config()["allow_connect"]:
        await refuse("live connections are switched off for this installation")
        return
    if not meta:
        await refuse("that SSH target is gone"); return
    if not _may_target(me, tid):
        await refuse("your roles do not include this target"); return
    if meta["is_prod"] and ws.query_params.get("confirm", "") != meta["name"]:
        await refuse(f"{meta['name']} is production — type its name to connect")
        return
    ip = _client_ip(ws)
    where = f"{meta['name']} · {meta['address']}"
    just = pam.justification(ws.query_params.get("ticket", ""),
                             ws.query_params.get("stime", ""),
                             ws.query_params.get("summary", ""))
    if pam.reason_required(meta["is_prod"]) and not just:
        await refuse("this target needs a ticket URL, a session time and a "
                     "summary before a session opens — reconnect from the target "
                     "page"); return
    just = just or {}
    cfg = pam.config()
    if cfg["max_concurrent"] and pam.concurrent_for(
            me.get("email", "")) >= cfg["max_concurrent"]:
        await refuse(f"you already hold {cfg['max_concurrent']} live session(s) — "
                     "the concurrent-session limit for this installation"); return
    try:
        term = await run_in_threadpool(pam.open_ssh, tid, rows, cols)
    except pam.Refused as e:
        await refuse(str(e)); return
    auth.audit(me, "pam_ssh", where, _pam_opened_detail(just), ip)
    typed = kmanage.pty_audit_line()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    used: set = set()
    last_input = [time.time()]                   # for the idle-timeout guard
    rec = pam.start_recording(
        me.get("email", "anonymous"), ip, protocol="ssh", target_id=tid,
        target_name=meta["name"], address=meta["address"], pid=meta["pid"],
        rgid=meta["rgid"], source=meta["source"], rec_kind="asciinema",
        reason=just.get("summary", ""), ticket=just.get("ticket", ""),
        session_time=just.get("session_time", ""), rows=rows, cols=cols)
    sid = rec.id if rec else ""
    if sid:
        pam.register_active(sid, {"who": me.get("email", ""),
                                  "target": meta["name"], "target_id": tid,
                                  "address": meta["address"],
                                  "protocol": "ssh", "ip": ip,
                                  # The growing asciinema cast. Held here so a
                                  # supervisor can watch the session AS IT RUNS
                                  # rather than only after it closes — the row
                                  # never carries the path itself.
                                  "cast": (rec.cast.path if rec and rec.cast
                                           else "")},
                            lambda: term.close())

    def record(lines):
        for line in lines:
            auth.audit(me, "pam_ssh", where, line, ip)
        if rec:
            rec.commands_typed(lines)

    async def to_browser():
        while True:
            try:
                data = await run_in_threadpool(term.read, 0.2)
            except EOFError:
                return
            if data:
                text = decoder.decode(data)
                typed.saw_output(text)
                if rec:
                    rec.output(text)
                await ws.send_text(text)
            record(typed.due())

    async def to_host():
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if "r" in msg:
                r, c = int(msg["r"][0]), int(msg["r"][1])
                await run_in_threadpool(term.resize, r, c)
                if rec:
                    rec.resize(r, c)
                continue
            keys = str(msg.get("i", ""))
            if not keys:
                continue
            used.add(1)
            last_input[0] = time.time()
            record(typed.typed(keys))
            await run_in_threadpool(term.write, keys.encode("utf-8"))

    try:
        async with anyio.create_task_group() as tg:
            async def wrap(job):
                await job()
                tg.cancel_scope.cancel()

            async def guard():
                # Idle timeout and max duration — a session nobody is driving, or
                # one that has run too long, is ended by policy. Started outside
                # wrap(): returning must not itself close the session (with both
                # limits off it simply exits and the two pumps drive the close).
                idle, maxd = cfg["idle_timeout"], cfg["max_duration"]
                # THE DECLARED TIME IS A LIMIT NOW, not a note. It was
                # recorded on the row and folded into an audit line, and
                # nothing read it back -- so somebody who said "30 minutes" on
                # a production target got a session bounded only by the
                # install-wide maximum, which on most installs is nothing.
                # Whichever is SHORTER wins: an operator may bound themselves
                # tighter than the install, never looser.
                cap = pam.session_cap_seconds(just.get("session_time", ""))
                if cap:
                    maxd = min(maxd, cap) if maxd else cap
                if not idle and not maxd:
                    return
                opened = time.time()
                while True:
                    await anyio.sleep(5)
                    now = time.time()
                    why = ("reached its maximum duration"
                           if maxd and now - opened >= maxd else
                           "closed for inactivity"
                           if idle and now - last_input[0] >= idle else "")
                    if why:
                        with contextlib.suppress(Exception):
                            await ws.send_text(
                                f"\r\n\x1b[33m— session {why}.\x1b[0m\r\n")
                        auth.audit(me, "pam_ssh", where, f"session {why}", ip)
                        tg.cancel_scope.cancel()
                        return

            tg.start_soon(wrap, to_browser)
            tg.start_soon(wrap, to_host)
            tg.start_soon(guard)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        code = term.proc.poll()
        failed = not used and code not in (0, None)
        with anyio.CancelScope(shield=True):
            await run_in_threadpool(term.close)
            pam.drop_session_dir(getattr(term, "workdir", ""))
        record(typed.close())
        if rec:
            await run_in_threadpool(rec.finish, "failed" if failed else "closed")
        if sid:
            pam.drop_active(sid)
        auth.audit(me, "pam_ssh", where,
                   (f"session failed to start (ssh exit {code})" if failed
                    else f"session closed after "
                         f"{round(time.time() - term.opened)}s"), ip)
        with contextlib.suppress(RuntimeError):
            await ws.close(code=4001) if failed else await ws.close()


# ── PAM: RDP / VNC over Apache Guacamole ───────────────────────
@app.get("/pam/targets/{tid}/launch")
def pam_launch(request: Request, tid: str):
    """Open a web target — and LEAVE A TRACE, which is the only thing the
    portal can honestly contribute here.

    A web target is NOT proxied: the browser goes straight to the application,
    so there is no live session to watch and no recording to keep, and nothing
    on this path pretends otherwise. Reported as "I added a web application
    but I cannot see a live session or a recording for it" — correct, and the
    page had been claiming the opposite in two places ("launched with the
    brokered credential"), which is what created the expectation.

    What this route adds is the half that was missing altogether. The button
    was a plain `<a href>` straight out of the row, so:

      * opening a PRODUCTION application out of the privileged-access
        catalogue left **no record at all** — and evidence is the one thing
        this whole section of the product exists to produce; and
      * the stored URL went into an `href` unchecked, which is a stored XSS
        (`javascript:` executes — there is no CSP here). Fixed at the write
        side too, in `pam._web_url`; this route is the second half, because
        the href is now a portal address and the stored value never reaches
        the page as markup.

    It grants nobody anything: the address is in the catalogue in front of
    them, so gating this behind the connect permission would only make the
    portal less useful than a bookmark. Reading the catalogue is the gate, and
    the per-target scope still applies.
    """
    t = pam.target(tid)
    if not t or t.get("protocol") not in ("http", "https"):
        return RedirectResponse(_pam_back(
            "targets", err="that is not a web target"), 303)
    me = getattr(request.state, "user", None)
    if not _may_target(me, tid):
        return RedirectResponse(_pam_back(
            "targets", err="your roles do not include this target"), 303)
    # PRODUCTION IS REACHED THROUGH THE RECORDED CONSOLE, AND ONLY THAT. This
    # route deliberately grants nothing -- the address is in the catalogue in
    # front of the reader -- but on production the point is not the grant, it
    # is the EVIDENCE. Going straight from somebody's own browser leaves an
    # audit line saying it happened and nothing that can be replayed, watched,
    # or shown to anybody afterwards, which is the whole reason this section of
    # the product exists.
    #
    # Enforced HERE and not only in the catalogue: the row hides the button,
    # and a hidden button is not a control -- this address is guessable from
    # any other target's and was reachable by typing it.
    if t.get("is_prod"):
        refusal = ("that target is production, so it is reached through the "
                   "recorded console only — opening it directly would leave "
                   "nothing but an audit line")
        auth.audit(me, "pam_web_open_refused", t["name"],
                   "production web target · direct open refused",
                   _client_ip(request))
        return RedirectResponse(_pam_back("targets", err=refusal), 303)
    url = pam.web_url(t)
    if not url:
        return RedirectResponse(_pam_back(
            "targets", err=f"{t['name']} has no usable http(s) address — open "
            "its page and set one"), 303)
    auth.audit(me, "pam_web_opened", t["name"],
               f"{'production ' if t.get('is_prod') else ''}web target · {url}"
               " · opened directly, not proxied or recorded",
               _client_ip(request))
    return RedirectResponse(url, 303)


@app.get("/pam/targets/{tid}/console", response_class=HTMLResponse)
def pam_console(request: Request, tid: str, confirm: str = "", ticket: str = "",
                stime: str = "", summary: str = "", win: str = ""):
    """A live desktop on a target, rendered by guacamole-common-js.

    RDP and VNC point guacd at the target itself. A WEB target points it at a
    browser this portal starts for the session — same page, same socket, same
    recording; see app/webseat.py for why that is the only way an HTTP
    application can become something watchable.
    """
    if (why := _may_connect(request)):
        return RedirectResponse(_pam_back("targets", err=why), 303)
    t = pam.target(tid)
    web = (t or {}).get("protocol") in ("http", "https")
    if not t or (t.get("protocol") not in pam.GUAC_PROTOCOLS and not web):
        return RedirectResponse(_pam_back("targets",
                                          err="that is not an RDP or VNC target"), 303)
    if web and (why := webseat.why_unavailable(pam.config())):
        return RedirectResponse(_pam_back("targets", err=why), 303)
    if not _may_target(getattr(request.state, "user", None), tid):
        return RedirectResponse(_pam_back(
            "targets", err="your roles do not include this target"), 303)
    if not pam.config()["allow_connect"]:
        return RedirectResponse(_pam_back(
            "targets", err="live connections are switched off"), 303)
    if not pam.guacd_reachable():
        return RedirectResponse(_pam_back(
            "targets", err="the RDP/VNC gateway (guacd) is not reachable — an "
            "administrator sets it in Settings → Privileged Access"), 303)
    if (gate := _pam_preconnect(request, t, "console", confirm, ticket, stime,
                                summary, bool(win))):
        return gate
    # `win` MEANS THIS IS ITS OWN WINDOW, so the portal's frame is dropped and
    # the session gets the whole of it. Carried in the URL rather than sniffed
    # from `window.opener`, because the page has to know before it renders --
    # and because a link somebody bookmarks or reopens then behaves the same
    # way it did the first time.
    return templates.TemplateResponse(
        request, "pam_console.html", ctx(request, t=t, confirm=confirm,
                                         ticket=ticket, stime=stime,
                                         summary=summary, bare=bool(win)))


@app.get("/pam/session/{sid}/shadow", response_class=HTMLResponse)
def pam_shadow(request: Request, sid: str, mode: str = "watch"):
    """Watch a live graphical session, or take the keyboard on it.

    The same page the operator is looking at, joined through guacd — see
    `pam_shadow_socket` for how, and for why watching is read-only by
    construction rather than by policy. Reading rides the `pam` area; taking
    control is checked here AND at the socket, because a page that offers a
    button the socket will refuse is a page that lies.
    """
    me = getattr(request.state, "user", None)
    take = (mode or "").strip().lower() == "control"
    tid = pam.active_target(sid) or ""
    if not tid:
        return RedirectResponse(_pam_back(
            "active", err="that session is not open any more"), 303)
    if not rbac.may_target(me, tid, "pam"):
        return RedirectResponse(_pam_back(
            "active", err="that session is not one of your targets"), 303)
    if not pam.guac_id_of(sid):
        return RedirectResponse(_pam_back(
            "active", err="only a recorded desktop session can be watched "
            "while it runs — an SSH session is watched from its own window"),
            303)
    if take:
        if (why := _may_connect(request)):
            return RedirectResponse(_pam_back("active", err=why), 303)
        if not pam.config()["allow_connect"]:
            return RedirectResponse(_pam_back(
                "active", err="live connections are switched off"), 303)
        if not _may_target(me, tid):
            return RedirectResponse(_pam_back(
                "active", err="your roles do not include this target"), 303)
    row = next((a for a in (pam.active_sessions() or [])
                if a.get("id") == sid), {})
    t = pam.target(tid) or {"id": tid, "name": row.get("target", "session"),
                            "address": row.get("address", ""),
                            "proto_label": row.get("proto_label", ""),
                            "is_prod": 0}
    return templates.TemplateResponse(
        request, "pam_console.html",
        ctx(request, t=t, confirm="", ticket="", stime="", summary="",
            join={"sid": sid, "mode": "control" if take else "watch",
                  "who": row.get("who", "somebody")}))


async def _read_guac_instr(reader: asyncio.StreamReader) -> list:
    """Read one guacd instruction (LEN.VALUE,…;). Used only for the `args` reply,
    which is ASCII, so reading LEN bytes for LEN characters is exact here; the
    display stream that follows is piped raw, never parsed."""
    elems = []
    while True:
        lb = b""
        while (ch := await reader.readexactly(1)) != b".":
            lb += ch
            if len(lb) > 8:
                raise ValueError("guacd length field too long")
        val = await reader.readexactly(int(lb))
        term = await reader.readexactly(1)
        elems.append(val.decode("utf-8", "replace"))
        if term == b";":
            return elems


@app.websocket("/pam/guac.ws")
async def pam_guac_socket(ws: WebSocket, tid: str = "", w: int = 0, h: int = 0):
    """Relay one browser to guacd, and guacd to the target's RDP/VNC. The portal
    completes guacd's handshake with the brokered credential, then pipes the
    display stream both ways; guacd writes the session recording itself."""
    # guacamole-common-js opens the socket with the "guacamole" subprotocol and
    # fails the connection if the server does not echo it — the tunnel needs it.
    await ws.accept(subprotocol="guacamole")
    me = _ws_pam(ws)
    t = pam._target_raw(tid)

    async def refuse(text: str) -> None:
        with contextlib.suppress(Exception):
            await ws.close(code=4001, reason=text[:110])

    if not me:
        await refuse("you do not have Privileged Access: connect"); return
    if not pam.config()["allow_connect"]:
        await refuse("live connections are switched off"); return
    web = (t or {}).get("protocol") in ("http", "https")
    if not t or (t.get("protocol") not in pam.GUAC_PROTOCOLS and not web):
        await refuse("that RDP/VNC target is gone"); return
    if web and (why := webseat.why_unavailable(pam.config())):
        # Said before anything is created, and in the words the settings page
        # would use — a half-built session that fails on the third step tells
        # the reader nothing about which switch is off.
        await refuse(why); return
    if not _may_target(me, tid):
        await refuse("your roles do not include this target"); return
    if t.get("is_prod") and ws.query_params.get("confirm", "") != t["name"]:
        await refuse(f"{t['name']} is production — confirm its name first"); return
    ip = _client_ip(ws)
    where = f"{t['name']} · {t['address']}"
    just = pam.justification(ws.query_params.get("ticket", ""),
                             ws.query_params.get("stime", ""),
                             ws.query_params.get("summary", ""))
    if pam.reason_required(t.get("is_prod")) and not just:
        await refuse("this target needs a ticket URL, a session time and a "
                     "summary before a session opens — reconnect from the target "
                     "page"); return
    just = just or {}
    gcfg = pam.config()
    if gcfg["max_concurrent"] and pam.concurrent_for(
            me.get("email", "")) >= gcfg["max_concurrent"]:
        await refuse(f"you already hold {gcfg['max_concurrent']} live session(s) — "
                     "the concurrent-session limit for this installation"); return

    rec = pam.start_recording(
        me.get("email", "anonymous"), ip, protocol=t["protocol"],
        target_id=t["id"], target_name=t["name"], address=t["address"],
        pid=t.get("proj_id", ""), rgid=t.get("rgn_id", ""), source="pam",
        rec_kind="guac", reason=just.get("summary", ""),
        ticket=just.get("ticket", ""), session_time=just.get("session_time", ""))
    sid = rec.id if rec else ""

    # Open guacd and complete its handshake with the target's parameters. For a
    # WEB target the parameters describe a browser this portal just started —
    # guacd renders the browser, and the browser is what visits the
    # application. See app/webseat.py.
    seat = None
    # KEEP THE TUNNEL ALIVE WHILE THE SEAT IS BUILT. Nothing can be sent to
    # the browser until guacd's handshake completes, and building a browser
    # pod takes far longer than the client's receive timeout — so it gave up
    # and reported "Server timeout" while the pod was still starting, leaving
    # a 0-second session behind it. A `nop` is the protocol's own no-op: it
    # resets the client's timer and says nothing else.
    async def _hold_open() -> None:
        # AND SAY WHAT THE CLUSTER IS DOING, not what we imagine it is doing.
        # The pane could only count seconds and then assert a cause; on
        # somebody else's cluster the true reason is usually something
        # Kubernetes states outright — the image cannot be pulled from that
        # registry, no node will take the pod. `name` is the protocol's own
        # instruction for labelling a connection, so the client is told in a
        # way it already understands.
        said = ""
        while True:
            await anyio.sleep(3)
            with contextlib.suppress(Exception):
                now = webseat.progress(sid) if sid else ""
                if now and now != said:
                    said = now
                    await ws.send_text(pam.guac_instr("name", now).decode())
                else:
                    await ws.send_text(pam.guac_instr("nop").decode())

    try:
        if web:
            # ANYIO WRAPS AN ESCAPING EXCEPTION IN A GROUP, so the seat's own
            # reason has to be carried out of the task group by hand. It was
            # raised inside the body, and the reader was told "unhandled
            # errors in a TaskGroup (1 sub-exception)" while the sentence that
            # names the step that failed — the only part anybody can act on —
            # was thrown away. That cost an afternoon of diagnosing the wrong
            # thing, because the audit line recorded the wrapper too.
            seat_err: BaseException | None = None
            async with anyio.create_task_group() as warm:
                warm.start_soon(_hold_open)
                try:
                    # THE SEAT IS BUILT FOR THIS SCREEN. Rendering at a
                    # configured size and scaling the picture into the pane
                    # resampled it AND made the application lay itself out for
                    # a viewport nobody was looking at.
                    webseat.remember_screen(w, h)
                    seat = await run_in_threadpool(
                        webseat.open_seat, pam.config(), pam.web_url(t), sid,
                        pam.web_also(t), (w, h))
                except BaseException as e:  # noqa: BLE001
                    seat_err = e
                finally:
                    warm.cancel_scope.cancel()
            if seat_err is not None:
                raise seat_err
            protocol, params = pam.guac_web_params(seat, w, h)
            # REPLACE THE SPARE WE JUST TOOK, while this person uses it. Not
            # awaited: their session must not wait on the next one's image
            # pull, and if it fails the only cost is that the NEXT click is
            # the slow one it used to be.
            with contextlib.suppress(Exception):
                _sp = pam.config()
                if int(_sp.get("web_spares") or 0):
                    asyncio.get_running_loop().run_in_executor(
                        None, webseat.ensure_spares, _sp)
        else:  # noqa: RET505
            protocol, params = pam.guac_params(t, w, h)
        if rec:
            params.update(pam.guac_recording_params(sid))
        cfg = pam.config()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cfg["guacd_host"], cfg["guacd_port"]), 5)
        writer.write(pam.guac_instr("select", protocol))
        await writer.drain()
        args = await asyncio.wait_for(_read_guac_instr(reader), 5)
        if not args or args[0] != "args":
            raise RuntimeError("guacd did not offer a parameter list")
        writer.write(pam.guac_instr("size", params["width"], params["height"],
                                    params["dpi"]))
        writer.write(pam.guac_instr("audio"))
        writer.write(pam.guac_instr("video"))
        # WEBP TOO, and this is a CLIENT capability list -- it says what the
        # browser on the other end can decode, and guacd picks from it. It was
        # png and jpeg only, which meant this end was claiming the browser
        # could decode nothing better than the two oldest formats guacd has.
        #
        # AND IT BOUGHT ALMOST NOTHING, measured rather than assumed. Against a
        # real page scrolling at 1600x900, through this guacd (1.5.5, whose VNC
        # client and libguac both link libwebp -- checked inside the running
        # container), mean bytes per scroll:
        #
        #   24-bit png+jpeg   342 KiB     what shipped before
        #   24-bit webp       335 KiB     -2%, which is noise
        #
        # So guacd is not choosing WebP for this workload, and the honest note
        # to the next reader is that this line is NOT the lag fix. It stays
        # because it is free and correct -- a browser running
        # guacamole-common-js can decode WebP, a guacd built without libwebp
        # ignores the offer, and another workload or a later guacd may take it.
        # Nothing is claimed for it.
        #
        # Declared on BOTH sockets -- the console and the watch socket -- since
        # a supervisor watching a session goes through the other one.
        writer.write(pam.guac_instr("image", "image/webp",
                                    "image/png", "image/jpeg"))
        writer.write(pam.guac_instr(
            "connect", *pam.guac_connect_values(args[1:], params)))
        await writer.drain()
        # READ `ready` RATHER THAN PIPING IT, because its argument is guacd's
        # own connection id and that id is the only way a supervisor can join
        # this session while it runs. It is then forwarded verbatim — the
        # client needs it to reach CONNECTED, and it also carries the id the
        # browser echoes back.
        hello = await asyncio.wait_for(_read_guac_instr(reader), 10)
        if not hello or hello[0] != "ready":
            raise RuntimeError(f"guacd did not become ready ({hello[:1]})")
        guac_conn_id = hello[1] if len(hello) > 1 else ""
        await ws.send_text(pam.guac_instr(*hello).decode())
    except webseat.Refused as e:
        # The seat's own refusals are sentences somebody can act on — which
        # step failed, and in whose cluster. Do not flatten them into
        # "could not reach the gateway".
        if seat:
            await run_in_threadpool(seat.close)
        if rec:
            await run_in_threadpool(rec.finish, "failed")
        # AUDITED, because a ws close reason lives only in the browser that
        # got it. A session filed as `failed` with the reason nowhere is a
        # session nobody can diagnose — which is exactly what happened: a
        # seat failed after 75s and the only record was a status column.
        auth.audit(me, "pam_console_failed", where, str(e)[:400], ip)
        await refuse(str(e))
        return
    except Exception as e:                                      # noqa: BLE001
        if seat:
            await run_in_threadpool(seat.close)
        if rec:
            await run_in_threadpool(rec.finish, "failed")
        auth.audit(me, "pam_console_failed", where,
                   f"{type(e).__name__}: {str(e)[:300]}", ip)
        await refuse(f"could not reach the gateway: {type(e).__name__}")
        return

    auth.audit(me, "pam_console", where,
               f"{protocol.upper()} " + _pam_opened_detail(just), ip)
    if sid:
        # No `cast`: guacd writes the RDP/VNC recording in its own format for
        # its own player, so there is nothing to tail. The row reports
        # unwatchable and the page says so, rather than offering a control that
        # would open an empty window.
        pam.register_active(sid, {"who": me.get("email", ""),
                                  "target": t["name"], "target_id": t["id"],
                                  "address": t["address"],
                                  "protocol": protocol, "ip": ip,
                                  # WRITTEN AT REGISTRATION, not after it: the
                                  # handshake happens before this row exists,
                                  # so setting it separately would drop the id
                                  # and the session would report unwatchable
                                  # for its whole life.
                                  "guac_id": guac_conn_id},
                            lambda: writer.close())
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    framer = pam.GuacFramer()
    last_input = [time.time()]                   # for the idle-timeout guard

    async def guac_to_browser():
        # The browser's tunnel parses each message on its own, so only whole
        # instructions may cross — the framer holds back a split trailing one.
        while True:
            # BIGGER READS, FEWER MESSAGES. Measured on a realistic frame --
            # 195 KiB of guac text for one full-surface scroll at 1600x900 --
            # a 16 KiB read produced FIVE websocket messages per frame where
            # one would do, and each costs a frame header here and a parse in
            # the browser's tunnel. The re-framing itself is not the cost
            # (0.07 ms per frame, measured); the message count was.
            data = await reader.read(GUAC_READ)
            if not data:
                return
            out = framer.feed(decoder.decode(data))
            if out:
                await ws.send_text(out)

    async def browser_to_guac():
        while True:
            msg = await ws.receive_text()
            last_input[0] = time.time()
            writer.write(msg.encode("utf-8"))
            await writer.drain()

    async def guard():
        # Idle timeout and max duration for the desktop session — see the SSH
        # relay for the shape. On a graphical session there is no line to print,
        # so it sends a guac error instruction (the client shows a disconnect)
        # and cancels.
        idle, maxd = gcfg["idle_timeout"], gcfg["max_duration"]
        # The same rule as the SSH relay: the declared session length is a
        # limit, and the shorter of it and the install's own maximum wins.
        _cap = pam.session_cap_seconds(just.get("session_time", ""))
        if _cap:
            maxd = min(maxd, _cap) if maxd else _cap
        if not idle and not maxd:
            return
        opened = time.time()
        while True:
            await anyio.sleep(5)
            now = time.time()
            why = ("reached its maximum duration"
                   if maxd and now - opened >= maxd else
                   "closed for inactivity"
                   if idle and now - last_input[0] >= idle else "")
            if why:
                with contextlib.suppress(Exception):
                    await ws.send_text(
                        pam.guac_instr("error", f"session {why}", "0").decode())
                auth.audit(me, "pam_console", where, f"session {why}", ip)
                tg.cancel_scope.cancel()
                return

    try:
        async with anyio.create_task_group() as tg:
            async def wrap(job):
                await job()
                tg.cancel_scope.cancel()
            tg.start_soon(wrap, guac_to_browser)
            tg.start_soon(wrap, browser_to_guac)
            tg.start_soon(guard)
    # A relay ends when either side goes away; whichever raises, it arrives
    # wrapped in the task group's ExceptionGroup. Any of these means "the session
    # is over" — the finally below is what actually cleans up.
    except (WebSocketDisconnect, RuntimeError, OSError, anyio.EndOfStream,
            BaseExceptionGroup):
        pass
    finally:
        with anyio.CancelScope(shield=True):
            # THE SIGN-OFF GOES FIRST, while guacd is still listening. Ordering
            # is the whole trick: guacd stops writing the recording the moment
            # its socket closes, so a farewell drawn after `writer.close()`
            # would be shown to nobody and recorded onto nothing. Reported
            # after watching a recording back — the last thing on it was the
            # browser image's own desktop.
            if seat:
                b = store.brand()
                with contextlib.suppress(Exception):
                    # NAME ONLY. The brand's subtitle is an organisation's
                    # name, and a recording is evidence rather than a place to
                    # sign the work — see brand_page. The second argument is
                    # for the product's own address, once there is a page.
                    await run_in_threadpool(seat.farewell, b["name"], "",
                                            not b["branded"])
            with contextlib.suppress(Exception):
                writer.close()
            # SHIELDED, and before the recording is filed: the browser holds a
            # pod, a port-forward and a WebDriver session, and the one outcome
            # worth engineering against is a browser left logged in to a
            # production application because the socket dropped.
            if seat:
                await run_in_threadpool(seat.close)
            if rec:
                await run_in_threadpool(rec.finish, "closed")
        if sid:
            pam.drop_active(sid)
            webseat.forget(sid)
        auth.audit(me, "pam_console", where, f"{protocol.upper()} session closed",
                   ip)
        with contextlib.suppress(RuntimeError):
            await ws.close()


# ── PAM sessions (recordings) ──────────────────────────────────
def _ws_pam_read(ws: WebSocket):
    """The person behind a PAM socket if they may READ the access catalogue.

    Watching is reading — the same recording this reader may open the moment
    the session ends — so it rides the `pam` area, exactly as the SSH tail
    does. `_ws_pam` is the stricter one and stays for anything that touches a
    target.
    """
    u = current_user(ws)
    return u if u and rbac.may_area(u, "pam") else None


@app.websocket("/pam/session/{sid}/shadow.ws")
async def pam_shadow_socket(ws: WebSocket, sid: str, mode: str = "watch"):
    """Attach a supervisor to a live graphical session — watching, or taking it.

    HOW IT WORKS, because it is not a second stream
        guacd will let another client attach to a connection it is already
        running: `select $<connection id>` in place of `select vnc`. That
        second client is handed the SAME display, from the same guacd, so
        there is no second capture to keep in step and no second recording —
        the session's own recording already contains everything the supervisor
        sees. Verified against a live seat: the joiner received 840,433 bytes
        of the same screen the primary got 840,529 of.

    WATCH IS READ-ONLY BY CONSTRUCTION, NOT BY POLICY
        Nothing from the watcher's browser is written to guacd except `sync`,
        which is flow control and carries no input. There is no path from that
        window to the keyboard, so a read-only viewer cannot be talked into
        being anything else. Guacamole's own protocol would happily accept
        mouse and key from a joined user, which is exactly why the filter is
        here and not left to the far end.

    TAKING CONTROL IS A DIFFERENT ACT AND IS GATED LIKE ONE
        It is typing on somebody's production box, so it needs
        `pam_connect` — the same permission and the same install switch as
        opening a session — plus the per-target scope, and it is audited as
        its own event. Watching an over-the-shoulder session is oversight;
        taking the keyboard is access.
    """
    await ws.accept(subprotocol="guacamole")
    take = (mode or "").strip().lower() == "control"
    me = _ws_pam_read(ws)

    async def refuse(text: str):
        with contextlib.suppress(Exception):
            await ws.send_text(pam.guac_instr("error", text[:200], "0").decode())
            await ws.close(code=4001, reason=text[:110])

    if not me:
        await refuse("your role may not read the access catalogue")
        return
    if not pam.enabled():
        await refuse("privileged access is switched off on this portal")
        return
    tid = pam.active_target(sid) or ""
    if not tid:
        await refuse("that session is not open on this portal any more")
        return
    if not rbac.may_target(me, tid, "pam"):
        await refuse("that session is not one of your targets")
        return
    connid = pam.guac_id_of(sid)
    if not connid:
        await refuse("that session has no gateway connection to join — only a "
                     "recorded desktop session can be watched while it runs")
        return
    if take:
        # The connect permission, the install switch and the target scope —
        # the same three gates that stand in front of opening a session,
        # because this ends in the same place: a keyboard on that machine.
        if not rbac.may_area(me, "pam_connect"):
            await refuse("taking control of a session needs “Privileged "
                         "Access: connect”")
            return
        if not pam.config()["allow_connect"]:
            await refuse("live connections are switched off on this portal")
            return
        if not _may_target(me, tid):
            await refuse("you may not open a live session on that target")
            return

    ip = ws.client.host if ws.client else ""
    who = me.get("email", "")
    act = "pam_session_control" if take else "pam_session_watch"
    live = pam.active_sessions() or []
    whose = next((a.get("who", "") for a in live if a.get("id") == sid), "")
    where = f"session {sid} ({whose})"
    auth.audit(who, act, where,
               "took the keyboard" if take else "watching, read-only", ip)
    reader = writer = None
    try:
        cfg = pam.config()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(cfg["guacd_host"], cfg["guacd_port"]), 5)
        # JOIN, rather than connect: the id IS the protocol argument here.
        writer.write(pam.guac_instr("select", connid))
        await writer.drain()
        args = await asyncio.wait_for(_read_guac_instr(reader), 5)
        if not args or args[0] != "args":
            raise RuntimeError("the gateway did not offer a parameter list")
        # The joined connection is already running with its own parameters;
        # these only describe THIS viewer's display, and no recording
        # parameters are sent — the session is already being recorded once,
        # and a second writer would fight it for the same file.
        params = {"width": "1280", "height": "800", "dpi": "96"}
        writer.write(pam.guac_instr("size", params["width"], params["height"],
                                    params["dpi"]))
        writer.write(pam.guac_instr("audio"))
        writer.write(pam.guac_instr("video"))
        # WEBP TOO, and this is a CLIENT capability list -- it says what the
        # browser on the other end can decode, and guacd picks from it. It was
        # png and jpeg only, which meant this end was claiming the browser
        # could decode nothing better than the two oldest formats guacd has.
        #
        # AND IT BOUGHT ALMOST NOTHING, measured rather than assumed. Against a
        # real page scrolling at 1600x900, through this guacd (1.5.5, whose VNC
        # client and libguac both link libwebp -- checked inside the running
        # container), mean bytes per scroll:
        #
        #   24-bit png+jpeg   342 KiB     what shipped before
        #   24-bit webp       335 KiB     -2%, which is noise
        #
        # So guacd is not choosing WebP for this workload, and the honest note
        # to the next reader is that this line is NOT the lag fix. It stays
        # because it is free and correct -- a browser running
        # guacamole-common-js can decode WebP, a guacd built without libwebp
        # ignores the offer, and another workload or a later guacd may take it.
        # Nothing is claimed for it.
        #
        # Declared on BOTH sockets -- the console and the watch socket -- since
        # a supervisor watching a session goes through the other one.
        writer.write(pam.guac_instr("image", "image/webp",
                                    "image/png", "image/jpeg"))
        writer.write(pam.guac_instr(
            "connect", *pam.guac_connect_values(args[1:], params)))
        await writer.drain()
    except Exception as e:                                      # noqa: BLE001
        with contextlib.suppress(Exception):
            if writer:
                writer.close()
        await refuse(f"could not join that session: {type(e).__name__}")
        return

    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    framer = pam.GuacFramer()

    async def down():
        while True:
            # BIGGER READS, FEWER MESSAGES. Measured on a realistic frame --
            # 195 KiB of guac text for one full-surface scroll at 1600x900 --
            # a 16 KiB read produced FIVE websocket messages per frame where
            # one would do, and each costs a frame header here and a parse in
            # the browser's tunnel. The re-framing itself is not the cost
            # (0.07 ms per frame, measured); the message count was.
            data = await reader.read(GUAC_READ)
            if not data:
                return
            out = framer.feed(decoder.decode(data))
            if out:
                await ws.send_text(out)

    async def up():
        while True:
            msg = await ws.receive_text()
            # THE READ-ONLY GUARANTEE, in one call — see pam.guac_upstream.
            if (keep := pam.guac_upstream(msg, take)):
                writer.write(keep.encode("utf-8"))
                await writer.drain()

    try:
        async with anyio.create_task_group() as tg:
            async def wrap(job):
                await job()
                tg.cancel_scope.cancel()
            tg.start_soon(wrap, down)
            tg.start_soon(wrap, up)
    except (WebSocketDisconnect, RuntimeError, OSError, anyio.EndOfStream,
            BaseExceptionGroup):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()
        auth.audit(who, act, where,
                   "gave the keyboard back" if take else "stopped watching", ip)
        with contextlib.suppress(RuntimeError):
            await ws.close()



@app.get("/pam/sessions/{sid}", response_class=HTMLResponse)
def pam_session_page(request: Request, sid: str, msg: str = "", err: str = ""):
    row, ok = _pam_session_scoped(request, sid)
    if not row or not ok:
        return RedirectResponse(_pam_back(
            "sessions", err="that recording is gone" if not row
            else "your roles do not include that target"), 303)
    pam._placed([row])
    return templates.TemplateResponse(
        request, "pam_session.html",
        ctx(request, s=row, has_rec=bool(pam.session_rec_path(sid)),
            integ=pam.session_integrity(sid),
            proto_meta=pam.PROTOCOLS, msg=msg, err=err,
            may_connect=not _may_connect(request)))


@app.get("/pam/sessions/{sid}/recording")
def pam_session_recording(request: Request, sid: str):
    """The raw recording — an asciinema cast or a Guacamole recording."""
    row, ok = _pam_session_scoped(request, sid)
    if not row or not ok:
        raise HTTPException(status_code=404, detail="no recording")
    path = pam.session_rec_path(sid)
    if not path:
        raise HTTPException(status_code=404, detail="no recording")
    media = ("application/x-asciicast" if row.get("rec_kind") == "asciinema"
             else "application/octet-stream")
    return FileResponse(path, media_type=media, filename=os.path.basename(path))


@app.get("/pam/sessions/{sid}/commands.txt")
def pam_session_commands(request: Request, sid: str):
    row, ok = _pam_session_scoped(request, sid)
    if not row or not ok:
        raise HTTPException(status_code=404, detail="no such session")
    text = pam.session_commands_text(sid)
    auth.audit(getattr(request.state, "user", None), "pam_session_export",
               sid, "session commands", _client_ip(request))
    return Response(text, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition":
                             f'attachment; filename="{sid}-commands.txt"'})


@app.get("/pam/sessions/{sid}/transcript.txt")
def pam_session_transcript(request: Request, sid: str):
    """The whole session as text — prompts, commands and their output, what was
    on screen. The commands dialog shows this; the button downloads it."""
    row, ok = _pam_session_scoped(request, sid)
    if not row or not ok:
        raise HTTPException(status_code=404, detail="no transcript")
    text = pam.session_transcript_text(sid)
    if text is None:
        raise HTTPException(status_code=404, detail="no transcript")
    auth.audit(getattr(request.state, "user", None), "pam_session_export",
               sid, "session transcript", _client_ip(request))
    return Response(text, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition":
                             f'attachment; filename="{sid}-session.txt"'})


@app.get("/pam/commands.txt")
def pam_commands_report(request: Request, who: str = "", proj: str = "",
                        reg: str = ""):
    me = getattr(request.state, "user", None)
    text = pam.commands_for(who=who, pid=proj, rgid=reg,
                            visible=rbac.visible_targets(me, "pam"))
    stamp = time.strftime("%Y%m%d-%H%M")
    tag = "-".join(x for x in ("pam-commands", who or "all", stamp) if x)
    auth.audit(getattr(request.state, "user", None), "pam_commands_export",
               who or "all users", "", _client_ip(request))
    return Response(text, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition":
                             f'attachment; filename="{tag}.txt"'})


@app.post("/pam/session/delete")
async def pam_delete_session(request: Request):
    f = await request.form()
    if (why := _may_connect(request)):
        return RedirectResponse(_pam_back("sessions", err=why), 303)
    # DELETING EVIDENCE IS NOT PART OF THE GRANT THAT CREATES IT. Opening a
    # session and removing the record of one were the same permission, so
    # anybody who could use a target could erase what they did on it. See
    # rbac.may_pam_full.
    if not rbac.may_pam_full(getattr(request.state, "user", None)):
        return RedirectResponse(_pam_back("sessions",
                                err="deleting a recording needs the whole of "
                                    "Privileged Access, unrestricted"), 303)
    sid = str(f.get("sid") or "")
    row, ok = _pam_session_scoped(request, sid, area="pam_connect")
    if not row or not ok:
        return RedirectResponse(_pam_back("sessions",
                                err="that recording is not one of your targets"), 303)
    gone = await run_in_threadpool(pam.delete_session, sid)
    if gone and row:
        auth.audit(getattr(request.state, "user", None), "pam_session_deleted",
                   f"{row.get('who')}@{row.get('target_name') or row.get('address')}",
                   f"session {sid}", _client_ip(request))
    return RedirectResponse(_pam_back("sessions", msg="recording deleted" if gone
                                      else "that recording is gone"), 303)


@app.post("/pam/sessions/clear")
async def pam_clear_sessions(request: Request):
    f = await request.form()
    if (why := _may_connect(request)):
        return RedirectResponse(_pam_back("sessions", err=why), 303)
    me = getattr(request.state, "user", None)
    # And a BULK clear all the more so: this one deletes every recording
    # matching a filter.
    if not rbac.may_pam_full(me):
        return RedirectResponse(_pam_back("sessions",
                                err="clearing recordings needs the whole of "
                                    "Privileged Access, unrestricted"), 303)
    gone = await run_in_threadpool(pam.clear_sessions, str(f.get("proj") or ""),
                                   str(f.get("reg") or ""),
                                   str(f.get("who") or ""),
                                   rbac.visible_targets(me, "pam"))
    auth.audit(getattr(request.state, "user", None), "pam_sessions_cleared",
               str(f.get("who") or "all users"), f"{gone} recording(s)",
               _client_ip(request))
    return RedirectResponse(_pam_back("sessions", msg=f"{gone} recording(s) "
                            "deleted" if gone else "nothing to delete"), 303)


@app.post("/pam/session/{sid}/kill")
def pam_kill_session(request: Request, sid: str):
    if (why := _may_connect(request)):
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    if not rbac.may_target(me, pam.active_target(sid) or "", "pam_connect"):
        return JSONResponse({"ok": False,
                             "error": "that session is not one of your targets"}, 403)
    killed = pam.kill_active(sid)
    if killed:
        auth.audit(getattr(request.state, "user", None), "pam_session_killed",
                   sid, "live session ended by an operator", _client_ip(request))
    return JSONResponse({"ok": killed,
                         "error": "" if killed else "it is no longer live"})


# ── PAM: file transfer inside a live session ───────────────────
# WHY IT HANGS OFF A LIVE SESSION
#     Every gate lives on opening one — the connect permission, the install
#     switch, a justification where required, a production target's name typed.
#     Re-asking all of that per file would be a second copy of each, and typing
#     a production hostname once per FILE is not a gate. So a transfer is
#     something done inside a session already held: it inherits those gates, it
#     ends when the session does, and the person is demonstrably present.
#
#     It grants nothing new either way. Whoever has this session has an
#     interactive shell on that host through the same credential and can read
#     any file on it. What transfer adds is a file crossing the boundary
#     WITHOUT appearing in the session recording — a download is not terminal
#     output — so every one is audited by name, direction and size. In a PAM
#     that record is the feature.
def _sftp_door(request: Request, tid: str):
    """(target, session id, refusal). Every transfer route starts here."""
    if (why := _may_connect(request)):
        return None, "", why
    me = getattr(request.state, "user", None)
    if not _may_target(me, tid):
        return None, "", "that target is not one of yours"
    if not pam.config()["allow_connect"]:
        return None, "", ("live connections are switched off for this "
                          "installation")
    t = pam.target(tid)
    if not t or t.get("protocol") != "ssh":
        return None, "", "file transfer needs an SSH target"
    sid = pam.live_session_of((me or {}).get("email", ""), tid)
    if not sid:
        return None, "", ("open a session on this target first — files move "
                          "inside a session you are holding")
    return t, sid, ""


@app.get("/pam/targets/{tid}/sftp/list")
def pam_sftp_list(request: Request, tid: str, path: str = "."):
    """One directory on the target, over the session's own credential."""
    t, _sid, why = _sftp_door(request, tid)
    if why:
        return JSONResponse({"ok": False, "error": why}, 403)
    try:
        got = pam.sftp_list(tid, path or ".")
    except pam.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    return JSONResponse({"ok": not got["error"], **got})


@app.get("/pam/targets/{tid}/sftp/get")
def pam_sftp_get(request: Request, tid: str, path: str = ""):
    """Download one remote file to the person's own machine."""
    t, sid, why = _sftp_door(request, tid)
    if why:
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    ip = _client_ip(request)
    try:
        # EVERY outcome is audited, refusals included. The first version logged
        # only what succeeded, so a download that failed at the connection —
        # or was refused for being a directory or too large — left no trace of
        # having been ASKED for. In a PAM the attempt is the interesting half:
        # somebody reaching for /etc/shadow and missing is exactly the line an
        # investigation wants.
        def refuse(msg: str, code: int = 400):
            auth.audit(me, "pam_sftp_download", f"{t['name']}:{path}",
                       f"refused: {msg}", ip)
            return JSONResponse({"ok": False, "error": msg}, code)

        st = pam.sftp_stat(tid, path)
        if st["error"]:
            return refuse(st["error"])
        if st["dir"]:
            return refuse("that is a directory")
        # Refused BEFORE the bytes start landing, or a careless click fills the
        # disk the recordings live on.
        if st["size"] > pam.MAX_UPLOAD:
            return refuse(f"that file is {st['size'] // (1024 * 1024)}MB and "
                          f"the limit is "
                          f"{pam.MAX_UPLOAD // (1024 * 1024)}MB")
        work = pam.term_scratch()
        into = os.path.join(work, "download.bin")
        ok, err = pam.sftp_fetch(tid, path, into)
        if not ok:
            pam.drop_session_dir(work)
            return refuse(err)
        size = os.path.getsize(into)
        # THE RECORD. A file leaving a production host is the event this
        # product exists to be able to answer for, and the cast cannot see it.
        auth.audit(me, "pam_sftp_download", f"{t['name']}:{path}",
                   f"{size} bytes downloaded in session {sid}", ip)
        name = os.path.basename(path.rstrip("/")) or "download"
        return FileResponse(
            into, filename=name, media_type="application/octet-stream",
            background=BackgroundTask(pam.drop_session_dir, work))
    except pam.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)


@app.post("/pam/targets/{tid}/sftp/put")
async def pam_sftp_put(request: Request, tid: str):
    """Upload one file from the person's machine into a remote directory."""
    t, sid, why = _sftp_door(request, tid)
    if why:
        return JSONResponse({"ok": False, "error": why}, 403)
    me = getattr(request.state, "user", None)
    ip = _client_ip(request)
    form = await request.form()
    up = form.get("file")
    where = str(form.get("path") or ".")
    if up is None or not getattr(up, "filename", ""):
        return JSONResponse({"ok": False, "error": "choose a file first"}, 400)
    work = pam.term_scratch()
    try:
        local = os.path.join(work, "upload.bin")
        size = 0
        with open(local, "wb") as fh:
            while chunk := await up.read(1024 * 1024):
                size += len(chunk)
                if size > pam.MAX_UPLOAD:
                    auth.audit(me, "pam_sftp_upload",
                               f"{t['name']}:{where}/{up.filename}",
                               "refused: over the size limit", ip)
                    return JSONResponse(
                        {"ok": False,
                         "error": f"the limit is "
                                  f"{pam.MAX_UPLOAD // (1024 * 1024)}MB"}, 413)
                fh.write(chunk)
        ok, err = pam.sftp_send(tid, local, where, up.filename)
        auth.audit(me, "pam_sftp_upload",
                   f"{t['name']}:{where}/{up.filename}",
                   (f"{size} bytes uploaded in session {sid}" if ok
                    else f"refused: {err}"), ip)
        return JSONResponse({"ok": ok, "error": err, "size": size})
    except pam.Refused as e:
        return JSONResponse({"ok": False, "error": str(e)}, 400)
    finally:
        pam.drop_session_dir(work)


# One poll never returns more than this. A session that dumps a
# large file still streams to the watcher, a chunk per poll, instead
# of one response big enough to stall the browser.
CHUNK_CAP = 256 * 1024


@app.get("/pam/session/{sid}/live.json")
def pam_watch_session(request: Request, sid: str, frm: int = 0):
    """The new bytes of a live session's recording, for watching it as it runs.

    WHY A TAIL AND NOT A SECOND STREAM
        The session is already writing an asciinema cast, line-buffered, so the
        frames are on disk the instant the host prints them. Tailing that file
        is watching the session — with no second copy of the stream to keep in
        step, and no way for the watcher to reach the terminal. A supervisor
        watches; only the person at the keyboard types.

    Gated by the `pam` AREA, not `pam_connect`. Watching is reading a recording
    — the same recording this same reader may open the moment the session ends
    — so requiring the connect permission would be stricter than the thing it
    protects. The per-target scope still applies, so a scoped operator watches
    only sessions on their own targets, and ending one still needs
    `pam_connect`.
    """
    me = getattr(request.state, "user", None)
    tid = pam.active_target(sid) or ""
    live = bool(tid)
    if live and not rbac.may_target(me, tid, "pam"):
        return JSONResponse({"ok": False,
                             "error": "that session is not one of your targets"},
                            403)
    path = pam.live_cast(sid)
    if not path:
        # Not an error: a session that has just closed is the normal way this
        # ends, and the watcher is told so it can stop polling and say so.
        return JSONResponse({"ok": True, "live": False, "text": "",
                             "next": frm, "done": True})
    try:
        size = os.path.getsize(path)
        start = max(0, min(int(frm or 0), size))
        with open(path, "rb") as fh:
            fh.seek(start)
            chunk = fh.read(CHUNK_CAP)
        # Never split a UTF-8 sequence across polls — the tail resumes exactly
        # where this stopped, so dropping the partial tail is lossless.
        text = chunk.decode("utf-8", "ignore")
        return JSONResponse({"ok": True, "live": live, "done": not live,
                             "text": text, "next": start + len(chunk)})
    except OSError as e:
        return JSONResponse({"ok": False, "error": str(e)[:160]}, 500)


# ── MCP: the portal as tools an AI client can call ─────────────
@app.post("/mcp")
async def mcp_rpc(request: Request):
    """The MCP endpoint — Streamable HTTP, JSON-RPC 2.0, stateless.

    Authenticated by the middleware, which has already resolved the token to a
    person; everything below runs as them. The body is handled in a worker
    thread because a tool call reads live clusters and far-away APIs, and this
    endpoint must not hold the event loop while a kubeconfig times out.
    """
    me = getattr(request.state, "user", None)
    try:
        body = await request.json()
    except Exception:                                         # noqa: BLE001
        return JSONResponse({"jsonrpc": "2.0", "id": None,
                             "error": {"code": mcp.PARSE_ERROR,
                                       "message": "invalid JSON"}},
                            status_code=400)
    out = await run_in_threadpool(mcp.dispatch, me, body, _client_ip(request),
                                  getattr(request.state, "mcp_token", None))
    # A notification gets no body at all. 202 is what the specification asks
    # for, and a client that receives {} instead waits for a correlation that
    # never comes.
    if out is None:
        return Response(status_code=202)
    return JSONResponse(out)


@app.api_route("/mcp", methods=["GET", "DELETE"])
def mcp_no_stream():
    """This server offers no server-initiated stream and keeps no session, so
    both of those are 405 — which is exactly what the specification says to
    answer rather than inventing an empty stream."""
    return JSONResponse({"error": "this MCP endpoint accepts POST only"},
                        status_code=405, headers={"Allow": "POST"})


def _mcp_base(request: Request) -> str:
    """The address to build a connect command from.

    A configured base wins, because that is the only value somebody has
    asserted. Falling back to the request's own origin is right for a laptop
    reading the page and wrong as a default — so the page says which it used.
    """
    return (mailer.public_base()
            or str(request.base_url).rstrip("/"))


@app.get("/settings/mcp", response_class=HTMLResponse)
def settings_mcp(request: Request, msg: str = "", err: str = "",
                 sec: str = ""):
    me = getattr(request.state, "user", None)
    base = _mcp_base(request)
    # Shown once, and only to the person who just minted it: held in their
    # session rather than passed through the URL, because a secret in a query
    # string is a secret in a proxy log and a browser history.
    fresh = request.session.pop("mcp_new_token", "")
    return templates.TemplateResponse(
        request, "set_mcp.html",
        ctx(request, cfg=mcp.config(), rows=mcp.tokens(),
            mine=mcp.tokens((me or {}).get("id", "")),
            # The register names people, not ids: "mt-1a2b belongs to u-5d1e"
            # is not something anybody can act on.
            owners={uid: u.get("email") or uid
                    for uid, u in auth.users().items()},
            base=base, base_set=bool(mailer.public_base()),
            endpoint=mcp.endpoint(base), fresh=fresh,
            command=mcp.client_command(base, fresh),
            client_json=mcp.client_json(base, fresh),
            may_mcp=rbac.may_area(me, "mcp"),
            # Pure view state: the route forwards which tab and derives nothing
            # else from it — the house rule for subtabs.
            sec=sec if sec in ("connect", "tokens", "server", "tools")
                else "connect",
            areas=[(a, rbac.AREAS[a][0]) for a in mcp.readable_areas()],
            modes=mcp.MODE_WORDS, may_manage=rbac.may_area(me, "manage"),
            # (verb, label) pairs for the scope chips, and the same catalogue
            # again for the "what a client can do" card — read from the
            # registry rather than written out on the page, so the two cannot
            # drift from what the server actually offers.
            act_names=[(n, n) for n in sorted(actions.CATALOGUE)],
            verbs=sorted(actions.available(me, may_change=True),
                         key=lambda v: (v["changes"], v["name"])),
            tool_count=len(mcp.tools(me)), msg=msg, err=err))


@app.post("/settings/mcp")
async def settings_mcp_save(request: Request):
    f = await request.form()
    me = getattr(request.state, "user", None)
    was = mcp.config()
    now_on = bool(f.get("enabled"))
    now_act = bool(f.get("allow_actions"))
    mcp.save_config(enabled=now_on, allow_actions=now_act,
                    row_limit=f.get("row_limit"),
                    token_days=f.get("token_days"))
    for flag, then, now, what in (("enabled", was["enabled"], now_on, "server"),
                                  ("allow_actions", was["allow_actions"],
                                   now_act, "actions")):
        if then != now:
            auth.audit(me, f"mcp_{what}_" + ("enabled" if now else "disabled"),
                       "this installation", "", _client_ip(request))
    return RedirectResponse("/settings/mcp?msg=saved", 303)


@app.post("/me/mcp/token")
async def mcp_token_new(request: Request):
    """Mint a token for the signed-in person, and nobody else.

    Never for another account: a token acts AS its owner, so minting one for
    somebody else is impersonation with a paper trail pointing the wrong way.
    """
    me = getattr(request.state, "user", None)
    f = await request.form()
    back = ("/settings/mcp?sec=tokens" if str(f.get("back", "")) == "settings"
            else "/me")
    join = "&" if "?" in back else "?"
    if not me:
        return RedirectResponse("/login", 303)
    if not rbac.may_area(me, "mcp"):
        return RedirectResponse(
            f"{back}{join}err=" + urllib.parse.quote(
                "your roles do not include MCP access"), 303)
    # "lifetime" is its own choice in the form rather than a magic 0 somebody
    # has to know about, and it is audited by name because a token that never
    # expires is the one worth finding later.
    days = 0 if str(f.get("expiry", "")) == "never" else (f.get("days") or None)
    # The presets are resolved to the SAME three fields the custom controls
    # post, so there is one shape stored and no preset the reader has to
    # interpret later. "full" is deliberately an EMPTY narrowing rather than a
    # list of everything — a list would silently stop granting whatever gets
    # added next.
    preset = str(f.get("preset", "custom"))
    if preset == "read":
        areas, mode, verbs = [], "read", []
    elif preset == "full":
        areas, mode, verbs = [], "act", []
    else:
        areas, mode, verbs = (f.getlist("area"), str(f.get("mode", "read")),
                              f.getlist("act"))
    secret, row = mcp.mint(me["id"], str(f.get("name", "")), days,
                           areas=areas, mode=mode, actions=verbs)
    request.session["mcp_new_token"] = secret
    auth.audit(me, "mcp_token_created", row["name"],
               f"{row['id']}, expires {row['expires'] or 'NEVER (lifetime)'}, "
               f"{row['scope_words']}", _client_ip(request))
    return RedirectResponse(f"{back}{join}msg=" + urllib.parse.quote(
        "token created — copy it now, it is not shown again"), 303)


@app.post("/me/mcp/scope")
async def mcp_token_rescope(request: Request):
    """Change what one of your own tokens may do, without re-issuing it.

    A client already configured on somebody's laptop should not have to be
    reconnected to be given — or denied — the ability to act. The secret does
    not change; only what it may reach.
    """
    me = getattr(request.state, "user", None)
    f = await request.form()
    back = ("/settings/mcp?sec=tokens" if str(f.get("back", "")) == "settings"
            else "/me")
    join = "&" if "?" in back else "?"
    if not me:
        return RedirectResponse("/login", 303)
    got = mcp.rescope(str(f.get("id", "")), me["id"],
                      areas=f.getlist("area"),
                      mode=str(f.get("mode", "read")),
                      actions=f.getlist("act"))
    if got:
        auth.audit(me, "mcp_token_rescoped", got["name"],
                   f"{got['id']}, now {got['scope_words']}",
                   _client_ip(request))
    return RedirectResponse(f"{back}{join}msg=" + urllib.parse.quote(
        "token re-scoped" if got else "nothing to change"), 303)


@app.post("/me/mcp/revoke")
async def mcp_token_revoke_own(request: Request):
    me = getattr(request.state, "user", None)
    f = await request.form()
    back = ("/settings/mcp?sec=tokens" if str(f.get("back", "")) == "settings"
            else "/me")
    join = "&" if "?" in back else "?"
    # Confined to this person's own tokens, so a crafted id cannot reach
    # somebody else's. Revoking is operational, not destruction, so it is a
    # plain confirmation in the page.
    got = mcp.revoke(str(f.get("id", "")), (me or {}).get("id", ""))
    if got:
        auth.audit(me, "mcp_token_revoked", got["name"], got["id"],
                   _client_ip(request))
    return RedirectResponse(
        f"{back}{join}msg=" + urllib.parse.quote(
            "token revoked" if got else "nothing to revoke"), 303)


@app.post("/settings/mcp/revoke")
async def mcp_token_revoke_any(request: Request):
    """Revoke anybody's token. This is the register, and somebody has to be
    able to pull a credential belonging to a person who has left."""
    me = getattr(request.state, "user", None)
    f = await request.form()
    got = mcp.revoke(str(f.get("id", "")))
    if got:
        auth.audit(me, "mcp_token_revoked", got["name"],
                   f"{got['id']}, owner {got['uid']}", _client_ip(request))
    return RedirectResponse(
        "/settings/mcp?sec=tokens&msg=" + urllib.parse.quote(
            "token revoked" if got else "nothing to revoke"), 303)


@app.get("/settings/pam", response_class=HTMLResponse)
def settings_pam(request: Request, msg: str = ""):
    # Asked ONCE. `guacd_reachable` opens a socket and `gateway_state` calls
    # the API server, and a page that renders one card should not do either
    # twice. The Deployment is only consulted when the socket did not answer:
    # a working gateway has nothing to diagnose.
    ok = pam.guacd_reachable()
    return templates.TemplateResponse(
        request, "set_pam.html",
        ctx(request, cfg=pam.config(), guac_ok=ok,
            guacd_why=pam.guacd_why(), msg=msg,
            gw={} if ok else selfupdate.gateway_state(),
            gw_grant=selfupdate.enabled(),
            web_why=webseat.why_unavailable(pam.config()),
            web_clusters=webseat.cluster_options(),
            rec_mb=round(pam.store_bytes() / (1024 * 1024), 1)))


@app.post("/settings/pam")
async def settings_pam_save(request: Request):
    f = await request.form()
    me = getattr(request.state, "user", None)
    was = pam.config()["allow_connect"]
    now = bool(f.get("allow_connect"))
    was_on = pam.config()["enabled"]
    on = bool(f.get("enabled"))
    was_web = pam.config()["web_browser"]
    pam.save_config(enabled=on, allow_connect=now,
                    record_sessions=bool(f.get("record_sessions")),
                    guacd_host=f.get("guacd_host"),
                    guacd_port=f.get("guacd_port"),
                    guacd_image=f.get("guacd_image"),
                    rdp_width=f.get("rdp_width"), rdp_height=f.get("rdp_height"),
                    require_reason=f.get("require_reason"),
                    idle_timeout=f.get("idle_timeout"),
                    max_duration=f.get("max_duration"),
                    max_concurrent=f.get("max_concurrent"),
                    web_browser=bool(f.get("web_browser")),
                    web_image=f.get("web_image"),
                    web_cluster=f.get("web_cluster"),
                    web_namespace=f.get("web_namespace"),
                    web_vnc_port=f.get("web_vnc_port"),
                    web_driver_port=f.get("web_driver_port"),
                    web_vnc_password=f.get("web_vnc_password"),
                    web_seat_host=f.get("web_seat_host"),
                    web_ttl=f.get("web_ttl"),
                    web_spares=f.get("web_spares"),
                    web_cpu_req=f.get("web_cpu_req"),
                    web_mem_req=f.get("web_mem_req"),
                    web_cpu_lim=f.get("web_cpu_lim"),
                    web_mem_lim=f.get("web_mem_lim"),
                    web_ready_timeout=f.get("web_ready_timeout"),
                    web_page_timeout=f.get("web_page_timeout"),
                    keep_days=f.get("keep_days"),
                    keep_mb=f.get("keep_mb"))
    # Two switches, two audit lines. Turning the FEATURE on is the bigger
    # event of the two — it is what makes a recorded-session surface exist at
    # all — and reading "connections enabled" as the only record of that would
    # understate it.
    if was_on != on:
        auth.audit(me, "pam_" + ("enabled" if on else "disabled"),
                   "this installation", "", _client_ip(request))
    if was != now:
        auth.audit(me, "pam_connect_" + ("enabled" if now else "disabled"),
                   "this installation", "", _client_ip(request))
    # A third switch and a third line, for the same reason: this one starts
    # creating pods in somebody's cluster and pulling a browser image, which
    # is worth being able to find later.
    if was_web != bool(f.get("web_browser")):
        auth.audit(me, "pam_web_" + ("enabled" if f.get("web_browser")
                                     else "disabled"),
                   "this installation",
                   f"browsers in {pam.config()['web_cluster'] or 'no cluster'}"
                   f"/{pam.config()['web_namespace']}", _client_ip(request))
    return RedirectResponse("/settings/pam?msg=saved", 303)


@app.post("/settings/pam/gateway/start")
async def settings_pam_gateway_start(request: Request):
    """Add the RDP/VNC gateway sidecar to this install, from the page.

    WHY A BUTTON. A customer sent a screenshot of this page telling them to
    set a Helm value and run an upgrade — for a value that is already the
    default. The portal is running in the very Deployment that needs the
    container, and it already holds `patch` on exactly that object wherever
    self-update was granted, so the fix is one call rather than a support
    thread.

    IT DOES NOT REPLACE THE HELM VALUE, and the page says so: Helm still holds
    the release it rendered, so the next `helm upgrade` removes the sidecar
    again unless `guacd.enabled` is set there too. That is the same honest
    cost the one-click update carries, for the same reason.
    """
    me = getattr(request.state, "user", None)
    cfg = pam.config()
    # The button lives inside the settings form and posts it, so a gateway
    # image TYPED but not yet saved is right here. Preferring it is what
    # somebody means by editing that box and then pressing the button; the
    # stored value is the fallback.
    f = await request.form()
    image = (f.get("guacd_image") or "").strip() or cfg["guacd_image"]
    try:
        got = await run_in_threadpool(selfupdate.add_gateway, image,
                                      (me or {}).get("email", ""))
    except selfupdate.UpdateError as e:
        return RedirectResponse(
            f"/settings/pam?err={urllib.parse.quote(str(e))}", 303)
    auth.audit(me, "pam_gateway_added", got["image"],
               f"sidecar added to this deployment, data at {got['mount']} — "
               "Helm does not know, set guacd.enabled=true in the values",
               _client_ip(request))
    return RedirectResponse("/settings/pam?msg=" + urllib.parse.quote(
        "gateway added — the portal is restarting, and this reverts on the "
        "next helm upgrade unless you also set guacd.enabled=true"), 303)


@app.post("/settings/pam/web/sweep")
async def settings_pam_web_sweep(request: Request):
    """Remove browser pods this portal left behind.

    Not the primary guard — the pod's own `activeDeadlineSeconds` is, because
    it works when the portal is not running. This is for the restart case: a
    seat whose session died with the process has stopped, but it still
    occupies a name and a line in `kubectl get`, and somebody has to be able
    to tidy that without reaching for kubectl.
    """
    me = getattr(request.state, "user", None)
    try:
        gone = await run_in_threadpool(webseat.sweep, pam.config())
    except webseat.Refused as e:
        return RedirectResponse(f"/settings/pam?err={urllib.parse.quote(str(e))}",
                                303)
    if gone:
        auth.audit(me, "pam_web_swept", f"{len(gone)} browser pod(s)",
                   ", ".join(gone), _client_ip(request))
    msg = (f"removed {len(gone)} leftover browser pod(s)" if gone
           else "no leftover browser pods")
    return RedirectResponse(f"/settings/pam?msg={urllib.parse.quote(msg)}", 303)


# ── settings: a hub plus one page per concern ──────────────────
def _project_view() -> dict:
    view = {}
    for pid, p in store.projects().items():
        regions = {}
        for rgid, rg in p.get("regions", {}).items():
            envs = repo.list_envs(pid, rgid, include_hidden=True)
            bind = {e: repo.binding(pid, rgid, e) for e in envs}
            regions[rgid] = {**rg, "envs": envs,
                             # what each environment is DECLARED at — the pages
                             # show where files come from, whole
                             "bind": bind,
                             # is there anything to scan? Any live checkout —
                             # an environment's clone, or the legacy directory
                             # somebody planted files in by hand
                             "scannable": (store.repo_dir(pid, rgid).is_dir()
                                           or any(repo.checkout(pid, rgid, e).is_dir()
                                                  for e in envs))}
        view[pid] = {**p, "regions": regions}
    return view


@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request, msg: str = "", err: str = ""):
    projects = store.projects()
    clusters = sum(len(p.get("clusters", {})) for p in projects.values())
    return templates.TemplateResponse(
        request, "settings_hub.html",
        ctx(request, cards=[
            {"key": "projects", "icon": logos.glyph("folder-git-2", 30), "title": "Projects",
             "desc": "Create projects and manage their regions.",
             "count": f"{len(projects)} project" + ("s" if len(projects) != 1 else "")},
            {"key": "clusters", "find": "k8s kubeconfig sealed secrets namespaces gitops "
                                        "git repository branch values path", "icon": logos.logo("kubernetes", "Kubernetes", 30), "title": "Kubernetes clusters",
             "desc": "Kubeconfigs, sealing keys, GitOps repos, environment mapping.",
             "count": f"{clusters} cluster" + ("s" if clusters != 1 else "")},
            {"key": "pipelines", "find": "ci cd builds jobs", "icon": logos.glyph("zap", 30), "title": "Pipelines",
             "desc": "Jenkins, GitHub Actions, Bitbucket or GitLab CI.",
             "count": f"{len(store.all_ci())} connection"
                      + ("s" if len(store.all_ci()) != 1 else "")},
            {"key": "security", "find": "cve vulnerabilities findings sast scanning", "icon": logos.glyph("shield", 30), "title": "Security scanning",
             "desc": "DefectDojo, Dependency-Track or SonarQube.",
             "count": f"{len(store.all_sec())} connection"
                      + ("s" if len(store.all_sec()) != 1 else "")},
            {"key": "ansible", "icon": logos.glyph("wrench", 30),
             "title": "Ansible",
             "desc": "Whether this portal may change hosts, and how hard it "
                     "pushes when it does.",
             "count": ("real runs on" if ansible.config()["allow_real"]
                       else "check runs only")},
            {"key": "terraform", "icon": logos.glyph("boxes", 30),
             "title": "Terraform",
             "desc": "Whether this portal may apply or destroy infrastructure, "
                     "and how many resources it works on at once.",
             "count": ("apply on" if terraform.config()["allow_apply"]
                       else "plan only")},
            # The card is always here, off or on — it is how the feature gets
            # switched on, so hiding it while off left nothing to press.
            {"key": "pam", "find": "privileged access pam ssh rdp vnc session "
                                   "recording jump host bastion",
             "icon": logos.glyph("shield-check", 30),
             "title": "Privileged Access",
             "desc": "Whether this portal brokers and records live sessions at "
                     "all, whether they may be opened, and where the RDP/VNC "
                     "gateway lives.",
             "count": (("connections on" if pam.config()["allow_connect"]
                        else "catalogue only") if pam.enabled() else "off")},
            {"key": "mcp", "find": "claude tokens model context protocol assistant", "icon": logos.glyph("square-terminal", 30),
             "title": "AI clients (MCP)",
             "desc": "Let somebody's own Claude ask this portal the questions "
                     "the pages answer — over a token that carries only their "
                     "own permissions.",
             "count": (("actions on" if mcp.config()["allow_actions"]
                        else "read only") if mcp.enabled() else "off")},
            {"key": "logs", "find": "elk elastic loki search logging", "icon": logos.glyph("scroll-text", 30), "title": "Log platforms",
             "desc": "Elasticsearch, OpenSearch or Grafana Loki.",
             "count": f"{len(store.all_log())} connection"
                      + ("s" if len(store.all_log()) != 1 else "")},
            {"key": "mail", "find": "smtp relay outgoing mailbox notifications", "icon": logos.glyph("mail", 30), "title": "Email",
             "desc": "The relay that sends invitations and password resets — "
                     "and what makes a verified address verified.",
             "count": "configured" if mailer.configured() else "not set"},
            {"key": "deployment", "find": "environment variables env portal_ paths", "icon": logos.glyph("settings", 30), "title": "Deployment",
             "desc": "what the environment told this installation: paths, "
                     "binaries, session policy, branding.",
             "count": f"{sum(1 for r in env.summary() if r['set'])} set "
                      f"of {len(env.summary())}"},
            {"key": "monitoring", "find": "alerts metrics dashboards prometheus", "icon": logos.glyph("chart-line", 30), "title": "Monitoring",
             "desc": "Prometheus, Alertmanager, Grafana or Zabbix.",
             "count": f"{len(store.all_mon())} connection"
                      + ("s" if len(store.all_mon()) != 1 else "")},
            {"key": "storage", "find": "nas backups s3 buckets", "icon": logos.glyph("hard-drive", 30), "title": "Storage devices",
             "desc": "Backup targets: Synology, TrueNAS, MinIO, S3, NFS, SMB.",
             "count": f"{len(store.all_stor())} device"
                      + ("s" if len(store.all_stor()) != 1 else "")},
            {"key": "clouds", "find": "aws azure gcp alibaba iam", "icon": logos.glyph("cloud", 30), "title": "Cloud accounts",
             "desc": "AWS, Azure, Alibaba, Google Cloud — verified identities.",
             "count": f"{len(store.all_cloud())} account"
                      + ("s" if len(store.all_cloud()) != 1 else "")},
            {"key": "conns/edge", "find": "cdn waf certificates cache dns", "icon": logos.glyph("globe", 30), "title": "Edge & DNS",
             "desc": "Cloudflare, Fastly, Bunny, NS1 — DNS, TLS, cache and "
                     "what sits in front of everything.",
             "count": f"{len(store.all_edge())} provider"
                      + ("s" if len(store.all_edge()) != 1 else "")},
            {"key": "conns/gitops", "icon": logos.glyph("git-merge", 30), "title": "GitOps controllers",
             "desc": "Argo CD, or Flux read from a cluster you already added.",
             "count": f"{len(store.all_gitops())} controller"
                      + ("s" if len(store.all_gitops()) != 1 else "")},
            {"key": "conns/wf", "icon": logos.glyph("workflow", 30), "title": "Workflow engines",
             "desc": "Temporal and Airflow: what is running, what failed.",
             "count": f"{len(store.all_wf())} engine"
                      + ("s" if len(store.all_wf()) != 1 else "")},
            {"key": "conns/bmc", "icon": logos.glyph("cpu", 30), "title": "Server hardware",
             "desc": "iDRAC, iLO, XCC, Supermicro — one Redfish endpoint each.",
             "count": f"{len(store.all_bmc())} BMC"
                      + ("s" if len(store.all_bmc()) != 1 else "")},
            {"key": "assistant", "icon": logos.glyph("sparkles", 30), "title": "Assistant",
             "desc": "The model that answers questions about this estate.",
             "count": (assistant.config()["model"] or "not configured")
                      if assistant.ready() else "not configured"},
            {"key": "conns/db", "icon": logos.glyph("database", 30), "title": "Database servers",
             "desc": "PostgreSQL and MySQL/MariaDB, by host and port. "
                     "Credentials are typed at the console, never stored.",
             "count": f"{len(store.all_db())} server"
                      + ("s" if len(store.all_db()) != 1 else "")},
            {"key": "conns/vpn", "icon": logos.glyph("lock", 30), "title": "VPN portals",
             "desc": "Pritunl, OpenVPN Access Server, wg-easy or Netmaker — "
                     "who is connected, and which tunnels are up.",
             "count": f"{len(store.all_vpn())} portal"
                      + ("s" if len(store.all_vpn()) != 1 else "")},
            {"key": "conns/virt", "icon": "🧱", "title": "Hypervisors",
             "desc": "Proxmox VE, vCenter or a standalone ESXi host.",
             "count": f"{len(store.all_virt())} connection"
                      + ("s" if len(store.all_virt()) != 1 else "")},
        ], msg=msg, err=err))


@app.get("/settings/projects", response_class=HTMLResponse)
def settings_projects(request: Request, msg: str = "", err: str = ""):
    return templates.TemplateResponse(
        request, "set_projects.html", ctx(request, projects=_project_view(),
                                 msg=msg, err=err))


# GitOps repos had its own settings page — a region's URL, branch, credentials
# and values path, edited nowhere near the cluster that actually uses them.
# That is now the cluster form's own "serves environment" section: the
# repository, the branch, the path and (if it needs its own) the credentials,
# declared in the same submit that registers the cluster. /settings/repos (and
# any old link or bookmark, all of which anchored with a fragment — never sent
# to the server) redirects rather than 404s.
@app.get("/settings/repos")
def settings_repos():
    return RedirectResponse("/settings/clusters", 303)


@app.get("/settings/mail", response_class=HTMLResponse)
def settings_mail(request: Request, msg: str = "", err: str = ""):
    if not _admin(request):
        return templates.TemplateResponse(request, "denied.html", ctx(request),
                                          status_code=403)
    s = dict(mailer.settings())
    got_pw = bool(s.pop("password", ""))          # never sent to the browser
    s["has_password"] = got_pw
    # an environment variable wins over the stored value, and a box that looks
    # editable but is being overridden is worse than one that says so
    s["base_url_from_env"] = bool(env.BASE_URL)
    if env.BASE_URL:
        s["base_url"] = env.BASE_URL
    return templates.TemplateResponse(
        request, "set_mail.html",
        ctx(request, s=s, configured=mailer.configured(),
            security=mailer.SECURITY, msg=msg, err=err))


@app.post("/settings/mail")
async def settings_mail_save(request: Request):
    if not _admin(request):
        return RedirectResponse("/settings/mail?err=admins only", 303)
    f = await request.form()
    mailer.save(**{k: str(f.get(k, "")).strip()
                   for k in ("host", "port", "security", "username",
                             "from_addr", "from_name", "base_url")},
                password=str(f.get("password", "")))
    auth.audit(_admin(request), "mail_settings_saved",
               str(f.get("host", "")), ip=_client_ip(request))
    return RedirectResponse(_with("/settings/mail", "", msg="saved."), 303)


@app.post("/settings/mail/test")
async def settings_mail_test(request: Request):
    me = _admin(request)
    if not me:
        return RedirectResponse("/settings/mail?err=admins only", 303)
    f = await request.form()
    to = str(f.get("to", "")).strip()
    try:
        mailer.send(to, f"{store.brand()['name']} test message",
                    "This is a test from your portal. If it arrived, "
                    "invitations and password resets will too.\n")
    except ValueError as e:
        return RedirectResponse(_with("/settings/mail", "", err=str(e)), 303)
    auth.audit(me, "mail_test_sent", to, ip=_client_ip(request))
    return RedirectResponse(
        _with("/settings/mail", "", msg=f"sent to {to} — check it arrived."), 303)


@app.get("/about", response_class=HTMLResponse)
def about(request: Request, err: str = "", msg: str = "",
          updating: str = ""):
    """What am I running, and is it current?

    Every application has this page. This one did not, and the answer was
    spread across Settings → Deployment and the pod's logs —
    so the question a customer actually asks on a support call took three
    places to answer.

    Open to anyone who can sign in. It states facts about the installation and
    changes nothing; gating it would only mean the person on the call cannot
    read the version number back to you.
    """
    return templates.TemplateResponse(
        request, "about.html",
        _about_ctx(request, err=err, msg=msg, updating=updating))


def _about_ctx(request: Request, **extra) -> dict:
    """The About page's context, built in one place.

    Two routes render this template — the page itself and the answer to the
    update button, which must be a page rather than a redirect because there will
    be no process left to serve a second request.
    """
    import platform as _platform
    seen = updates.peek()
    base = dict(version=env.VERSION,
                # cache only: this page must not wait on somebody else's server
                upd=seen, tools=tools.check(),
                # what the button can do here, and if it cannot, why not. Only an
                # administrator is shown it: it restarts the service.
                selfupd=selfupdate.state(seen.get("latest", ""),
                                         bool(seen.get("available"))),
                can_update=bool(_admin(request)),
                drift=selfupdate.drift(),
                data_dir=str(env.DATA_DIR),
                python=_platform.python_version(),
                platform=f"{_platform.system()} {_platform.machine()}",
                release=os.environ.get("PORTAL_RELEASE_NAME", ""),
                err="", msg="", updating="")
    base.update(extra)
    return ctx(request, **base)


@app.post("/about/update")
async def about_update(request: Request):
    """Move this installation to the announced release.

    Decide, answer, then act — in that order, and the order is the whole point.
    The first version patched and then sent a redirect; the browser followed it
    into the gap where the pod had already been stopped, and a customer read "no
    available server" from the ingress while the update was in fact succeeding.

    So everything that can be refused is decided first, while there is still a
    process to say so. The patch runs as a background task, after the response
    has been flushed. And the page is built not to need this response at all.
    """
    me = _admin(request)
    wants_json = "application/json" in (request.headers.get("accept") or "")

    def refuse(message: str, code: int = 400):
        if wants_json:
            return JSONResponse({"error": message}, status_code=code)
        return RedirectResponse("/about?err=" + urllib.parse.quote(message[:400]),
                                303)

    if not me:
        return refuse("administrators only", 403)
    f = await request.form()
    want = str(f.get("version", ""))
    # The announced version is read here, not taken from the form. The form's
    # value is only allowed to agree with it.
    announced = (updates.peek().get("latest") or "")
    try:
        decided = await run_in_threadpool(selfupdate.plan, want, announced)
    except selfupdate.UpdateError as e:
        auth.audit(me, "self_update_refused", want, str(e)[:300],
                   _client_ip(request))
        return refuse(str(e))

    auth.audit(me, "self_update", f"{decided['from']} → {decided['to']}",
               decided["image"], _client_ip(request))
    # Only now, and only after this response is on the wire.
    after = BackgroundTask(selfupdate.commit, decided,
                           (me or {}).get("email", ""))
    if wants_json:
        return JSONResponse({"updating": decided["to"]}, status_code=202,
                            background=after)
    # No JavaScript: one response, not a redirect to a second one that cannot be
    # served. This page carries the poller and needs nothing further.
    return templates.TemplateResponse(
        request, "about.html", _about_ctx(request, updating=decided["to"]),
        background=after)


@app.get("/settings/deployment", response_class=HTMLResponse)
def settings_deployment(request: Request, msg: str = "", err: str = ""):
    """What this installation was told by its environment.

    Shown rather than hidden: "why is it behaving like that" should be answerable
    from the running portal, not only from the chart that installed it.
    """
    seen = updates.peek()
    return templates.TemplateResponse(
        request, "set_deployment.html",
        ctx(request, rows=env.summary(), data_dir=str(env.DATA_DIR),
            tools=tools.check(force=bool(request.query_params.get("recheck"))),
            # cache only: rendering a settings page must not wait on somebody
            # else's web server
            upd=seen, snaps=snapshot.taken(), keep=snapshot.KEEP,
            # the same update button the About page carries, from the same
            # include — so the two pages cannot disagree about whether this
            # installation can update itself
            selfupd=selfupdate.state(seen.get("latest", ""),
                                     bool(seen.get("available"))),
            can_update=bool(_admin(request)),
            release=os.environ.get("PORTAL_RELEASE_NAME", ""),
            updating=str(request.query_params.get("updating") or ""),
            version=env.VERSION, msg=msg, err=err))


@app.post("/settings/deployment/check-updates")
def settings_check_updates(request: Request):
    if not _admin(request):
        return RedirectResponse("/settings/deployment?err=admins only", 303)
    got = updates.check(force=True)
    if got.get("error"):
        return RedirectResponse(_with("/settings/deployment", "",
                                      err=got["error"]), 303)
    if got.get("available"):
        msg = f"{got['latest']} is available — you are running {got['current']}."
    else:
        msg = f"up to date on {got['current']}."
    return RedirectResponse(_with("/settings/deployment", "", msg=msg), 303)


@app.get("/settings/clusters", response_class=HTMLResponse)
def settings_clusters(request: Request, msg: str = "", err: str = "",
                      show: str = "", q: str = ""):
    """Every cluster, and which environment each one serves.

    The page used to render a full edit form — two textareas and all — for every
    cluster, which is fine at three and about ten thousand pixels of scrolling
    at twenty-five. So the heavy lifting is here instead: the counts the tiles
    filter by, and WHERE EACH CLUSTER IS USED, which is the half of the mapping
    nobody could see. Reading it from the cluster's side ("this one serves
    KE/preprod") answers the question people actually arrive with, and it costs
    one pass over the regions rather than a second query per row.
    """
    view = _project_view()
    # WHERE EACH CLUSTER IS USED comes from the MAPPING, not from what is on
    # disk: an environment can be assigned before a single values file exists
    # for it, and reading this from the files made those assignments invisible
    # — which is what made them look impossible to create. `files` says
    # whether anything is behind it yet, which is worth showing and is a
    # different question from whether the assignment is real. The enriched
    # view is passed in so `bind` and `files` are populated.
    used = store.serves(view)
    clusters = [(pid, cid, c) for pid, p in view.items()
                for cid, c in (p.get("clusters") or {}).items()]
    # THE DOT IS LIVE, not the last time somebody pressed `test`.
    #
    # It used to read `c.status`, a string written only by the test button — so
    # sixteen of twenty-four clusters were permanently grey, including every one
    # the portal talks to all day on other pages. Grey read as "down" and it
    # meant "nobody has clicked test on this since it was registered".
    #
    # `fleet.peek()` is the snapshot the landing page and /clusters are already
    # made of, kept warm by the warmer: it never blocks (None until the first
    # collection finishes, and asking warms it), so the settings page pays
    # nothing for the truth. The stored status stays as the fallback for a
    # cluster the snapshot has no opinion on yet, and the three states are kept
    # apart — up, down, and NOT YET KNOWN — because collapsing the third into
    # either of the others is the bug being fixed.
    snap = fleet.peek() or {}
    live = {h["cid"]: h for h in (snap.get("clusters") or [])}
    for _pid, cid, c in clusters:
        h = live.get(cid)
        if h:
            n = h.get("nodes") or {}
            c["live"] = "ok" if h.get("reachable") else "bad"
            c["live_why"] = (
                f"connected — {n.get('ready', 0)}/{n.get('total', 0)} nodes ready"
                if h.get("reachable")
                else (h.get("error") or "did not answer"))
        else:
            # No snapshot entry: say so rather than borrowing the stored verdict
            # and presenting it as current. A tested-once-last-month "ok" shown
            # as a green dot is the same lie in the other direction.
            c["live"] = ""
            c["live_why"] = ("not collected yet" if snap
                             else "the fleet snapshot is still being built")
    totals = {
        "clusters": len(clusters), "projects": len(view),
        "manage": sum(1 for _p, _c, c in clusters if c.get("manage")),
        "nokey": sum(1 for _p, _c, c in clusters if not c.get("cert_file")),
        "unused": sum(1 for _p, cid, _c in clusters if cid not in used),
        "down": sum(1 for _p, _c, c in clusters if c.get("live") == "bad"),
    }
    return templates.TemplateResponse(
        request, "set_clusters.html",
        ctx(request, projects=view, used=used, totals=totals,
            show=show if show in ("manage", "nokey", "unused", "down") else "",
            q=q.strip(), msg=msg, err=err))


@app.get("/settings/project/{pid}/cluster/form", response_class=HTMLResponse)
def cluster_form(request: Request, pid: str, cid: str = ""):
    """One cluster's form, for the window to fetch. Blank `cid` = add a new one.

    The list used to carry twenty-four of these expanded in its own HTML — two
    textareas apiece, whether or not anybody opened one — which was 463K and
    the largest document the portal served. Fetching one on demand is what lets
    the list be a plain sortable table.

    It re-reads `_project_view()` rather than being handed a cluster: the form
    needs every project's regions (the project select re-filters the region
    list in the browser) and the environments this cluster serves, and building
    that here keeps the fragment identical to what the page would have rendered
    inline.
    """
    view = _project_view()
    p = view.get(pid)
    if not p:
        return HTMLResponse("<p class='cl-note'>that project is gone</p>",
                            status_code=404)
    if cid and cid not in (p.get("clusters") or {}):
        return HTMLResponse("<p class='cl-note'>that cluster is gone — reload "
                            "the page</p>", status_code=404)
    used = store.serves({pid: p}, pid)
    return templates.TemplateResponse(
        request, "_cluster_form.html",
        ctx(request, pid=pid, cid=cid, c=(p.get("clusters") or {}).get(cid),
            p=p, projects=view, used=used))


@app.get("/settings/pipelines", response_class=HTMLResponse)
def settings_pipelines(request: Request, msg: str = "", err: str = ""):
    return templates.TemplateResponse(
        request, "set_pipelines.html",
        ctx(request, ci_conns=store.all_ci(), providers=ci.PROVIDERS,
            ci_notes={k: v["note"] for k, v in ci.PROVIDERS.items()},
            project_names={k: v["name"] for k, v in store.projects().items()},
            msg=msg, err=err))


@app.get("/settings/security", response_class=HTMLResponse)
def settings_security(request: Request, msg: str = "", err: str = ""):
    return templates.TemplateResponse(
        request, "set_security.html",
        ctx(request, sec_conns=store.all_sec(), providers=security.PROVIDERS,
            sec_notes={k: v["note"] for k, v in security.PROVIDERS.items()},
            sec_scopes={k: {"label": v["scope_label"], "hint": v["scope_hint"]}
                        for k, v in security.PROVIDERS.items()},
            project_names={k: v["name"] for k, v in store.projects().items()},
            msg=msg, err=err))


@app.get("/settings/monitoring", response_class=HTMLResponse)
def settings_monitoring(request: Request, msg: str = "", err: str = ""):
    return templates.TemplateResponse(
        request, "set_monitoring.html",
        ctx(request, mon_conns=store.all_mon(), providers=monitoring.PROVIDERS,
            mon_notes={k: v["note"] for k, v in monitoring.PROVIDERS.items()},
            mon_hints={k: v["url_hint"] for k, v in monitoring.PROVIDERS.items()},
            project_names={k: v["name"] for k, v in store.projects().items()},
            msg=msg, err=err))


@app.get("/settings/ansible", response_class=HTMLResponse)
def settings_ansible(request: Request, msg: str = "", err: str = ""):
    return templates.TemplateResponse(
        request, "set_ansible.html",
        ctx(request, cfg=ansible.config(), tool=ansible.tool(),
            summary=ansible.summary(), keep=ansible.RUNS_KEEP,
            msg=msg, err=err))


@app.post("/settings/ansible")
async def settings_ansible_save(request: Request):
    f = await request.form()
    was = ansible.config()["allow_real"]
    now = bool(f.get("allow_real"))
    ansible.save_config(allow_real=now, forks=f.get("forks"),
                        ssh_timeout=f.get("ssh_timeout"),
                        record_sessions=bool(f.get("record_sessions")))
    # Audited as its own line rather than as "settings changed": this is the
    # switch between a portal that reports and a portal that changes machines,
    # and somebody reading the trail afterwards wants to find the moment.
    if was != now:
        auth.audit(getattr(request.state, "user", None),
                   "ansible_real_runs_" + ("enabled" if now else "disabled"),
                   "this installation", "", _client_ip(request))
    return RedirectResponse("/settings/ansible?msg=saved", 303)


@app.get("/settings/logs", response_class=HTMLResponse)
def settings_logs(request: Request, msg: str = "", err: str = ""):
    return templates.TemplateResponse(
        request, "set_logs.html",
        ctx(request, log_conns=store.all_log(), providers=logstore.PROVIDERS,
            log_notes={k: v["note"] for k, v in logstore.PROVIDERS.items()},
            log_scopes={k: {"label": v["scope_label"], "hint": v["scope_hint"]}
                        for k, v in logstore.PROVIDERS.items()},
            project_names={k: v["name"] for k, v in store.projects().items()},
            msg=msg, err=err))


@app.post("/settings/project/new")
async def project_new(request: Request):
    """Create a project — from its settings page, or INLINE from a dropdown.

    `inline=1` answers JSON instead of redirecting: the cluster form's project
    dropdown offers "add a project…" right there, and a redirect would throw
    away everything already typed into that form — a pasted kubeconfig being
    the expensive case. One route either way, so there is exactly one creation
    path to gate and audit.
    """
    f = await request.form()
    name = str(f.get("name", "")).strip()
    inline = str(f.get("inline", "")) == "1"
    if not name:
        if inline:
            return JSONResponse({"error": "a project needs a name"},
                                status_code=400)
        return back(err="project name is required", to="/settings/projects")
    pid = store.add_project(name, str(f.get("icon", "")).strip(),
                            str(f.get("tagline", "")).strip())
    fleet.invalidate()   # fleet shape changed; drop the cached snapshot
    if inline:
        return JSONResponse({"id": pid, "name": name})
    return back(msg=f"project '{name}' created — now add a region",
                anchor=pid, to="/settings/projects")


@app.post("/settings/project/{pid}/update")
async def project_update(request: Request, pid: str):
    f = await request.form()
    store.update_project(pid, name=str(f.get("name", "")).strip(),
                         icon=str(f.get("icon", "")).strip(),
                         tagline=str(f.get("tagline", "")).strip(),
                         hidden_services=_csv(f.get("hidden_services")),
                         hidden_key_prefixes=_csv(f.get("hidden_key_prefixes")),
                         strip_suffixes=_csv(f.get("strip_suffixes")),
                         env_aliases=_pairs(f.get("env_aliases")),
                         values_globs=_csv(f.get("values_globs")),
                         layout_pattern=str(f.get("layout_pattern") or "").strip())
    return back(msg="project updated", anchor=pid, to="/settings/projects")


@app.post("/settings/project/{pid}/detect-layout")
async def project_detect_layout(request: Request, pid: str):
    """Scan a cloned region and auto-fill the repo layout (glob or pattern), so the
    user does not have to write one. Applies the best guess and shows the envs it
    found for a sanity-check."""
    d = await run_in_threadpool(repo.detect_layout_project, pid)
    if not d:
        return back(err="could not detect a layout — clone a region's repo first, or "
                        "nothing values-file-shaped was found under its values path",
                    anchor=pid, to="/settings/projects")
    store.update_project(pid, values_globs=d["globs"], layout_pattern=d["pattern"])
    envs = ", ".join(d["envs"][:8]) + ("…" if len(d["envs"]) > 8 else "")
    what = d["pattern"] or (", ".join(d["globs"]) if d["globs"] else "the default *-values*.yaml")
    return back(msg=f"detected & applied (from {d['region']}): {what} · "
                    f"{len(d['envs'])} environment(s) [{envs}] · {d['count']} service file(s) — review below",
                anchor=pid, to="/settings/projects")


@app.post("/settings/project/{pid}/delete")
def project_delete(pid: str):
    shutil.rmtree(store.REPOS / pid, ignore_errors=True)
    shutil.rmtree(store.SECRETS / pid, ignore_errors=True)
    fleet.invalidate()   # fleet shape changed; drop the cached snapshot
    store.delete_project(pid)
    return back(msg="project removed", to="/settings/projects")


# ── regions ────────────────────────────────────────────────────
@app.post("/settings/project/{pid}/region/new")
async def region_new(request: Request, pid: str):
    """Add a region — from the regions panel, or INLINE from a dropdown.

    Same shape as project_new's inline mode, for the same reason: the region
    dropdown on a half-filled cluster form must not cost the person the form.
    The JSON carries the rendered label (flag + name) so the new option looks
    exactly like the server-rendered ones.
    """
    f = await request.form()
    name = str(f.get("name", "")).strip()
    flag = str(f.get("flag", "")).strip()
    inline = str(f.get("inline", "")) == "1"
    to = _return_to(f)
    if not store.get_project(pid):
        if inline:
            return JSONResponse({"error": "that project is gone"},
                                status_code=404)
        return back(err="that project is gone", to="/settings/clusters")
    if not name:
        if inline:
            return JSONResponse({"error": "a region needs a name"},
                                status_code=400)
        return back(err="region name is required", anchor=pid, to=to)
    rgid = store.add_region(pid, name, flag, str(f.get("label", "")).strip())
    fleet.invalidate()   # fleet shape changed; drop the cached snapshot
    if inline:
        return JSONResponse({"id": rgid, "name": name,
                             "label": f"{config.flag_for(name, flag)} {name}"})
    return back(msg=f"region '{name}' added — now add a cluster and declare "
                    f"what it serves",
                anchor=rgid, to=to)


@app.post("/settings/project/{pid}/region/{rgid}/delete")
def region_delete(pid: str, rgid: str):
    shutil.rmtree(store.repo_dir(pid, rgid), ignore_errors=True)
    fleet.invalidate()   # fleet shape changed; drop the cached snapshot
    store.delete_region(pid, rgid)
    return back(msg="region removed", anchor=pid, to="/settings/clusters")


def _return_to(f, default: str = "/settings/clusters") -> str:
    """Where a settings form should land afterwards.

    The same forms appear on the settings page and on the live pages, so the
    form says where it came from. Only in-app paths are honoured — a redirect
    target that arrives with a request is how open redirects happen.
    """
    want = str(f.get("back", "") or "").strip()
    if want.startswith("/") and not want.startswith("//"):
        return want
    return default


@app.post("/settings/project/{pid}/region/{rgid}/sync")
async def region_sync(request: Request, pid: str, rgid: str):
    """Pull every checkout this region's environments read from.

    A region can span several repositories and branches now, so "sync the
    region" means one pull per DISTINCT checkout — never one per environment,
    or a four-environment monorepo would fetch the same clone four times.
    """
    f = await request.form()
    force = str(f.get("force", "")) == "1"
    nxt = str(f.get("next", "")) or ""
    to = _return_to(f, "/settings")

    def _sync_all() -> list[str]:
        done, seen, errs = [], set(), []
        for env in sorted(store.env_sources(pid, rgid)):
            b = repo.binding(pid, rgid, env)
            key = str(repo.checkout(pid, rgid, env))
            if not b["url"] or key in seen:
                continue
            seen.add(key)
            try:
                done.append(f"{env}: {gitrepo.sync_env(pid, rgid, env, force)}")
            except gitrepo.GitError as e:
                errs.append(f"{env}: {e}")
        if errs and not done:
            raise gitrepo.GitError("; ".join(errs)[:240])
        return done + [f"FAILED {e}" for e in errs]

    try:
        done = await run_in_threadpool(_sync_all)
    except gitrepo.GitError as e:
        msg = f"sync failed: {str(e)[:240]}"
        return (RedirectResponse(f"{nxt}?error={msg}", 303) if nxt
                else back(err=msg, anchor=rgid, to=to))
    msg = ("synced — " + "; ".join(done)[:220]) if done else \
          "nothing to sync — no environment here names a repository"
    return (RedirectResponse(f"{nxt}?saved={msg}", 303) if nxt
            else back(msg=msg, anchor=rgid, to=to))


async def _fetch_binding(pid: str, f) -> str:
    """Clone what a cluster form just declared, so the environment has files.

    The person named a repository; an empty checkout is not an answer.
    Reported as part of the same flash message rather than left for them to
    discover on the Config tab, which is where "why is this environment empty"
    comes from.

    Whether to fetch at all is `gitrepo.fetch_needed` — one definition shared
    with the environment-declaration route and the MCP verb.
    """
    rgid = str(f.get("region", "")).strip()
    env = str(f.get("env", "")).strip()
    if not rgid or not env or not store.get_region(pid, rgid):
        return ""
    if not gitrepo.fetch_needed(pid, rgid, env,
                                str(f.get("gitops_url", "")),
                                str(f.get("gitops_branch", ""))):
        return ""
    try:
        return " · " + await run_in_threadpool(gitrepo.sync_env, pid, rgid, env)
    except gitrepo.GitError as e:
        return f" · its repository could not be read: {e}"


def _binding_problem(path: str, url: str = "") -> str:
    """Why this environment binding cannot be stored, or "".

    Shape only. Whether the repository actually answers is a question for the
    connection test, which is the honest place for it — a form that guesses at
    URL validity rejects addresses that work.
    """
    path = str(path or "").strip().strip("/")
    if ".." in path.split("/"):
        return "that path leaves the repository"
    url = str(url or "").strip()
    # An absolute path is a repository address too: an air-gapped installation
    # mirrors GitOps locally and clones from /srv/git/x.git. Rejecting it would
    # be the portal deciding that everyone has internet.
    if url and not (url.startswith(("http://", "https://", "ssh://", "/"))
                    or ("@" in url and ":" in url)):
        return ("that does not look like a repository address — "
                "https://host/org/repo.git, git@host:org/repo.git or an "
                "absolute path to a local mirror")
    return ""


def _binding_from_form(pid: str, rgid: str, f, path=None) -> dict:
    """The {url, branch, path, protocol, username, secret} an environment is
    declared at.

    One reader for every form that carries the GitOps fields — the cluster
    form's "serves environment" section is the only one left — so there is one
    place that decides what a blank field means. Blank means INHERIT: the
    region's repository, the region's branch, the region's credentials. That is
    what makes the common case (one repository, a folder per environment) a
    name and nothing else. `secret` is handled write-only by `set_env_source`
    itself — blank there means "unchanged", not "cleared" — so it is passed
    through here exactly as typed, never defaulted to "".
    """
    out = {
        "url": str(f.get("gitops_url", "")).strip(),
        "branch": str(f.get("gitops_branch", "")).strip(),
        "path": str(f.get("gitops_path", "") if path is None
                    else path).strip().strip("/"),
        "protocol": str(f.get("gitops_protocol", "")).strip(),
        "username": str(f.get("gitops_username", "")).strip(),
    }
    secret = str(f.get("gitops_secret", ""))
    if secret:
        out["secret"] = secret
    return out


async def _write_env_ssh_key(pid: str, rgid: str, env: str, f) -> str:
    """Store an environment's own deploy key, if one was pasted.

    Validated with the SAME check the region's key goes through
    (`store.ssh_key_problem`) — a key this portal cannot use is worth refusing
    at the point of paste, not at the point of the next clone. Returns "" or the
    refusal.
    """
    key = str(f.get("gitops_ssh_key", ""))
    if not key.strip():
        return ""
    if (problem := store.ssh_key_problem(key)):
        return f"private key rejected: {problem}"
    store.write_ssh_key(pid, rgid, key, env)
    return ""


@app.post("/settings/project/{pid}/region/{rgid}/env/add")
async def region_env_add(request: Request, pid: str, rgid: str):
    """Declare an environment: a name, and where its values live.

    The only place this happens — there is no repository scan behind it any
    more. `repo.list_envs` applies what is declared here, so the whole portal
    sees it, not just this page.
    """
    f = await request.form()
    rg = store.get_region(pid, rgid)
    if not rg:
        return back(err="that region is gone", to="/settings/clusters")
    name = str(f.get("name", "")).strip()
    path = str(f.get("gitops_path", f.get("path", ""))).strip().strip("/")
    if not name:
        return back(err="an environment needs a name", anchor="mapping",
                    to="/settings/clusters")
    if "/" in name or name.startswith("."):
        return back(err="an environment name is one segment — no slashes",
                    anchor="mapping", to="/settings/clusters")
    if problem := _binding_problem(path, str(f.get("gitops_url", ""))):
        return back(err=problem, anchor="mapping", to="/settings/clusters")
    if problem := await _write_env_ssh_key(pid, rgid, name, f):
        return back(err=problem, anchor="mapping", to="/settings/clusters")
    bind = _binding_from_form(pid, rgid, f, path)
    displaced = store.set_env_source(pid, rgid, name, bind)
    b = repo.binding(pid, rgid, name)
    # An empty directory is not an answer to "where do its values live", so
    # fetch it now — declaring is the moment the person is watching, and the
    # moment a failure is worth reporting.
    #
    # `gitrepo.fetch_needed` owns the rule — see its docstring for the three
    # cases and the two bugs that shaped them. The MCP verb asks the same
    # function, so the form and the API cannot disagree about it.
    fetched = ""
    if gitrepo.fetch_needed(pid, rgid, name, bind.get("url", ""),
                            bind.get("branch", "")):
        try:
            fetched = " · " + await run_in_threadpool(
                gitrepo.sync_env, pid, rgid, name)
        except gitrepo.GitError as e:
            return back(err=f"{name} declared, but its repository could not be "
                            f"read: {e}", anchor="mapping",
                        to="/settings/clusters")
    found = len(repo.env_files(pid, rgid, name, include_hidden=True))
    auth.audit(getattr(request.state, "user", None), "env_declared",
               f"{rg.get('name', rgid)}/{name}",
               f"path {b['path'] or '(repository root)'}"
               + (f", branch {b['branch']}" if b["branch"] else "")
               + (f", repo {gitrepo.redact(b['url'])}" if b["url"] else "")
               + (", its own credentials" if b["has_own_auth"] else "")
               + f", {found} values file(s)",
               _client_ip(request))
    return back(msg=f"{name} declared at {b['path'] or 'the repository root'}"
                    + (f" on {b['branch']}" if b["branch"] else "")
                    + f" — {found} values file" + ("" if found == 1 else "s")
                    + " found"
                    + fetched
                    + (f"; “{displaced}” pointed at the same files and is no "
                       f"longer declared" if displaced else ""),
                anchor="mapping", to="/settings/clusters")


@app.get("/settings/project/{pid}/region/{rgid}/env/candidates")
def region_env_candidates(request: Request, pid: str, rgid: str):
    """What the repository looks like it holds — offered, not applied.

    Deliberately a separate call the person makes, not something a page load
    does. That is the whole difference between this and the scan it replaced:
    walking a checkout to SUGGEST is fine, walking it to decide what exists is
    what made the portal wrong for anyone with more than one repository.
    """
    if not store.get_region(pid, rgid):
        return JSONResponse({"error": "no such region"}, status_code=404)
    return JSONResponse({"candidates": repo.candidates(pid, rgid)})


@app.post("/settings/project/{pid}/region/{rgid}/env/sync")
async def region_env_sync(request: Request, pid: str, rgid: str):
    """Pull the checkout ONE environment reads from.

    The region's own Sync only ever touched the region's working copy, which is
    the wrong one for an environment bound to its own repository or branch — it
    would report success and change nothing the environment can see.
    """
    f = await request.form()
    name = str(f.get("name", "")).strip()
    to = _return_to(f)
    if not store.get_region(pid, rgid):
        return back(err="that region is gone", to=to)
    try:
        action = await run_in_threadpool(gitrepo.sync_env, pid, rgid, name,
                                         str(f.get("force", "")) == "1")
    except gitrepo.GitError as e:
        return back(err=f"{name}: {e}", anchor="mapping", to=to)
    found = len(repo.env_files(pid, rgid, name, include_hidden=True))
    auth.audit(getattr(request.state, "user", None), "env_synced",
               f"{rgid}/{name}", action, _client_ip(request))
    return back(msg=f"{name} {action} — {found} values file"
                    + ("" if found == 1 else "s"),
                anchor="mapping", to=to)


@app.post("/settings/project/{pid}/region/{rgid}/env/hide")
async def region_env_hide(request: Request, pid: str, rgid: str):
    """Undeclare an environment.

    Nothing in the repository is touched and the mapping is kept — this is the
    portal forgetting a declaration, not destroying a resource, which is why it
    is a plain confirm rather than the house typed-Delete gate.
    """
    f = await request.form()
    rg = store.get_region(pid, rgid)
    if not rg:
        return back(err="that region is gone", to="/settings/clusters")
    name = str(f.get("name", "")).strip()
    store.drop_env_source(pid, rgid, name)
    auth.audit(getattr(request.state, "user", None), "env_hidden",
               f"{rg.get('name', rgid)}/{name}",
               "declaration removed",
               _client_ip(request))
    return back(msg=f"{name} is no longer declared",
                anchor="mapping", to="/settings/clusters")


# ── clusters ───────────────────────────────────────────────────
def _env_blocks(f) -> list[dict]:
    """The form's environment blocks, in order, as parallel lists.

    A cluster serves as many environments as it serves — the dev cluster here
    runs UAE, CR and KE — and each one has its OWN path in the repository, and
    may have its own repository and branch entirely. The form used to carry one
    block and a note saying the others were edited elsewhere, so the reader saw
    one binding and reasonably concluded the rest had none. They did: CR/dev has
    had its own path all along, which is why the values showed up on the cluster
    page while the form looked empty. A form that shows one of three bindings is
    not a smaller form, it is a wrong one.

    Every block posts the same field NAMES, so the blocks are the positional
    zip of `getlist` — which is also what lets the browser add another block by
    cloning one, with nothing to renumber.
    """
    def col(name):
        return f.getlist(name) if hasattr(f, "getlist") else [f.get(name, "")]

    names = ("region", "env", "gitops_url", "gitops_branch", "gitops_path",
             "gitops_protocol", "gitops_username", "gitops_secret",
             "gitops_ssh_key")
    cols = {n: col(n) for n in names}
    depth = max((len(v) for v in cols.values()), default=0)
    out = []
    for i in range(depth):
        row = {n: str(cols[n][i]) if i < len(cols[n]) else "" for n in names}
        # A wholly empty block is the "add another" slot nobody filled in. It is
        # submitted on every save, so ignoring it here is what keeps saving an
        # unrelated field from declaring an environment called "".
        if row["region"].strip() or row["env"].strip():
            out.append(row)
    return out


async def _map_from_form(pid: str, cid: str, f) -> tuple[str, str]:
    """Declare EVERY environment this cluster serves, and where each one's
    values live — repository, branch, path, and its own credentials if it has
    any.

    This is the only place any of that is typed. A binding field left blank
    copies what this region's other environments share, so the ordinary case is
    still a region and a name.

    Returns (note, error). VALIDATED IN FULL BEFORE ANYTHING IS WRITTEN, in two
    passes. The one-pass version refused the second block after the first had
    already been stored, which left the form showing three environments and the
    database holding one and a half — the exact disagreement between what is on
    screen and what is saved that this page exists to remove. A cluster serving
    several environments makes that failure ordinary rather than theoretical, so
    the check has to finish before the writing starts.
    """
    blocks = _env_blocks(f)
    if not blocks:
        return "", ""

    # ── pass one: decide. Nothing here touches the database. ──
    work, seen = [], set()
    for b in blocks:
        rgid, env = b["region"].strip(), b["env"].strip()
        if not rgid or not env:
            return "", ("every environment needs both a region and a name — "
                        + ("a region is missing" if env
                           else f"a name is missing for the region you picked"))
        if not store.get_region(pid, rgid):
            continue
        if (rgid, env) in seen:
            return "", (f"{env} is listed twice for the same region — one block "
                        "per environment")
        seen.add((rgid, env))
        bind = {
            "url": b["gitops_url"].strip(),
            "branch": b["gitops_branch"].strip(),
            "path": b["gitops_path"].strip().strip("/"),
            "protocol": b["gitops_protocol"].strip(),
            "username": b["gitops_username"].strip(),
        }
        if b["gitops_secret"]:
            bind["secret"] = b["gitops_secret"]
        if problem := _binding_problem(bind["path"], bind["url"]):
            return "", f"{env}: {problem}"
        key = b["gitops_ssh_key"].strip()
        if key and (problem := store.ssh_key_problem(key)):
            return "", f"{env}: private key rejected: {problem}"
        work.append((rgid, env, bind, key))

    # ── pass two: write. Every block has already been accepted. ──
    notes = []
    for rgid, env, bind, key in work:
        if key:
            store.write_ssh_key(pid, rgid, key, env)
        # Only write a declaration when the block actually says something about
        # it, or when the environment has none yet. Otherwise saving an
        # unrelated field on a cluster would quietly blank a binding somebody
        # set earlier — a save that changes what it was not asked to change.
        declared = store.env_sources(pid, rgid)
        if any(bind.values()) or env not in declared:
            store.set_env_source(pid, rgid, env, bind)
        store.map_env_cluster(pid, rgid, env, cid)
        rg = store.get_region(pid, rgid) or {}
        got = repo.binding(pid, rgid, env)
        where = ""
        if got["url"]:
            where = f" from {gitrepo.redact(got['url'])}"
            if got["branch"]:
                where += f" ({got['branch']})"
            if got["path"]:
                where += f" at {got['path']}"
        notes.append(f"{rg.get('name', rgid)}/{env}{where}")
    if not notes:
        return "", ""
    return " · serving " + "; ".join(notes), ""


@app.post("/settings/project/{pid}/cluster/{cid}/unmap")
async def cluster_unmap(request: Request, pid: str, cid: str):
    """Stop a cluster serving one environment. The mapping is the region's, so
    this clears that entry rather than touching the cluster."""
    f = await request.form()
    rgid, env = str(f.get("region", "")), str(f.get("env", ""))
    rg = store.get_region(pid, rgid) or {}
    if (rg.get("env_clusters") or {}).get(env) == cid:
        store.map_env_cluster(pid, rgid, env, "")
        fleet.invalidate()
        return back(msg=f"{rg.get('name', rgid)}/{env} is no longer assigned",
                    anchor=pid, to="/settings/clusters")
    return back(err="that environment is not assigned to this cluster",
                anchor=pid, to="/settings/clusters")


@app.post("/settings/project/{pid}/cluster/new")
async def cluster_new(request: Request, pid: str):
    f = await request.form()
    # The form carries the project, so "add a cluster" is not tied to whichever
    # project's button was pressed. The URL's pid stays the fallback for a
    # submit that does not name one.
    want = str(f.get("project", "")).strip()
    if want and store.get_project(want):
        pid = want
    name = str(f.get("name", "")).strip()
    kubeconfig = str(f.get("kubeconfig", ""))
    cert = str(f.get("sealing_cert", ""))
    context = str(f.get("context", "")).strip()
    if not name:
        return back(err="cluster name is required", anchor=pid, to="/settings/clusters")
    if kubeconfig.strip():
        # just the kubeconfig is enough: it names its own current-context. The
        # typed context stays an optional override for a multi-context file.
        context, err = kube.resolve_context(kubeconfig, context)
        if err:
            return back(err=f"kubeconfig: {err}", anchor=pid, to="/settings/clusters")
    if cert.strip():
        ok, detail = sealing.validate_cert(cert)
        if not ok:
            return back(err=f"sealing certificate rejected: {detail}", anchor=pid, to="/settings/clusters")

    cid = store.add_cluster(pid, name, kubeconfig, context, cert)
    cluster = store.get_cluster(pid, cid)
    note = ""
    if kubeconfig.strip():
        ok, detail = await run_in_threadpool(kube.test_cluster, cluster)
        store.update_cluster(pid, cid, status=("ok: " if ok else "failed: ") + detail)
        note = " · " + detail
    mapped, problem = await _map_from_form(pid, cid, f)
    note += mapped + await _fetch_binding(pid, f)
    fleet.invalidate()   # fleet shape changed; drop the cached snapshot
    if problem:
        # the cluster IS added — refusing the whole submit over a path typo
        # would throw away a pasted kubeconfig
        return back(err=f"cluster '{name}' added, but the environment was not "
                        f"declared: {problem}", anchor=pid, to="/settings/clusters")
    return back(msg=f"cluster '{name}' added{note}", anchor=pid, to="/settings/clusters")


@app.post("/settings/project/{pid}/cluster/{cid}/update")
async def cluster_update(request: Request, pid: str, cid: str):
    f = await request.form()
    kubeconfig = str(f.get("kubeconfig", ""))
    cert = str(f.get("sealing_cert", ""))
    # A blank name is "the field was not submitted", never "call it nothing".
    # An empty string here went straight into the row and left a nameless
    # cluster that the list could only render as a gap.
    fields = {}
    if str(f.get("name", "")).strip():
        fields["name"] = str(f.get("name", "")).strip()
    context = str(f.get("context", "")).strip()
    # a pasted kubeconfig re-derives the context (its current-context) unless one
    # was typed; without a new kubeconfig, a typed context is an explicit override
    # and a blank one leaves the stored context untouched
    if kubeconfig.strip():
        context, err = kube.resolve_context(kubeconfig, context)
        if err:
            return back(err=f"kubeconfig: {err}", anchor=pid, to="/settings/clusters")
    if context:
        fields["context"] = context
    # management is off unless the checkbox is ticked on this save, so it can
    # never be left on by accident from an earlier edit
    fields["manage"] = "1" if str(f.get("manage", "")) else ""
    store.update_cluster(pid, cid, **fields)
    if cert.strip():
        ok, detail = sealing.validate_cert(cert)
        if not ok:
            return back(err=f"sealing certificate rejected: {detail}", anchor=pid, to="/settings/clusters")
    if kubeconfig.strip() or cert.strip():
        store.write_cluster_files(pid, cid, kubeconfig, cert)

    # Moving projects happens BEFORE the environment is read off the form: the
    # region named there belongs to the project the cluster is in now, and
    # mapping first would write an assignment `move_cluster` then clears.
    moved = ""
    want = str(f.get("project", "")).strip()
    if want and want != pid and store.get_project(want):
        gave_up = await run_in_threadpool(store.move_cluster, pid, cid, want)
        was, pid = pid, want
        moved = (f" · moved to {(store.get_project(want) or {}).get('name', want)}"
                 + (f", giving up {', '.join(gave_up)}" if gave_up else ""))
        auth.audit(getattr(request.state, "user", None), "cluster_moved",
                   (store.get_cluster(pid, cid) or {}).get("name", cid),
                   f"{was} → {want}"
                   + (f"; unassigned {', '.join(gave_up)}" if gave_up else ""),
                   _client_ip(request))
        fleet.invalidate()

    note, problem = await _map_from_form(pid, cid, f)
    note += await _fetch_binding(pid, f)
    if note or moved:
        fleet.invalidate()
    if problem:
        return back(err=f"cluster saved{moved}, but the environment was not "
                        f"declared: {problem}", anchor=pid,
                    to="/settings/clusters")
    return back(msg="cluster updated" + moved + note, anchor=pid,
                to="/settings/clusters")


@app.post("/settings/project/{pid}/cluster/{cid}/test")
def cluster_test(pid: str, cid: str):
    cluster = store.get_cluster(pid, cid) or {}
    ok, detail = kube.test_cluster(cluster)
    store.update_cluster(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    # to=, like every sibling route here. Without it back() falls back to
    # /settings — so pressing Test on a cluster threw you out of the page you
    # were working in, and the result appeared on the hub.
    return back(msg=detail if ok else "", err="" if ok else detail, anchor=pid,
                to="/settings/clusters")


@app.post("/settings/project/{pid}/cluster/{cid}/fetch-cert")
def cluster_fetch_cert(pid: str, cid: str):
    cluster = store.get_cluster(pid, cid) or {}
    try:
        pem = sealing.fetch_cert(cluster)
    except sealing.SealingError as e:
        return back(err=str(e), anchor=pid, to="/settings/clusters")
    store.write_cluster_files(pid, cid, sealing_cert=pem)
    ok, detail = sealing.validate_cert(pem)
    return back(msg=f"sealing certificate fetched — {detail}", anchor=pid, to="/settings/clusters")


@app.post("/settings/project/{pid}/cluster/{cid}/delete")
def cluster_delete(pid: str, cid: str):
    store.delete_cluster(pid, cid)
    fleet.invalidate()   # fleet shape changed; drop the cached snapshot
    return back(msg="cluster removed", anchor=pid, to="/settings/clusters")


# ── browsing ───────────────────────────────────────────────────
@app.get("/p/{pid}", response_class=HTMLResponse)
def project_home(request: Request, pid: str):
    p = store.get_project(pid)
    if not p:
        return RedirectResponse("/", 303)
    regions = {}
    for rgid, rg in p.get("regions", {}).items():
        envs = repo.list_envs(pid, rgid, include_hidden=True)
        regions[rgid] = {**rg, "env_count": len(envs),
                         "svc_count": sum(len(f) for f in envs.values()),
                         # does anything here read from a repository? The card
                         # warns when nothing does — per binding, since the
                         # region itself no longer has one
                         "has_repo": any(repo.binding(pid, rgid, e)["url"]
                                         for e in envs)}
    return templates.TemplateResponse(
        request, "project.html", ctx(request, pid, regions=regions))


@app.get("/p/{pid}/{rgid}", response_class=HTMLResponse)
def region_view(request: Request, pid: str, rgid: str):
    if not store.get_region(pid, rgid):
        return RedirectResponse(f"/p/{pid}", 303)
    envs = repo.list_envs(pid, rgid, include_hidden=True)
    clusters = {e: (store.cluster_for_env(pid, rgid, e) or {}).get("name")
                for e in envs}
    return templates.TemplateResponse(
        request, "region.html", ctx(request, pid, rgid, envs=envs, clusters=clusters))


@app.get("/p/{pid}/{rgid}/{env}", response_class=HTMLResponse)
def env_view(request: Request, pid: str, rgid: str, env: str, tab: str = "",
             stay: str = ""):
    """One environment.

    Clicking an environment always goes to the cluster page, never the standalone
    service list: to its serving cluster's Overview when one is mapped (config,
    pods and the drawing are all a tab away there), or to the project's cluster
    view when none is yet — where you assign one. `stay=1` renders the config-only
    view anyway, which is what the diagram's "full page" link uses.
    """
    cluster = store.cluster_for_env(pid, rgid, env)
    if not stay:
        cid = (cluster or {}).get("id", "")
        if cid:
            want = "diagram" if tab == "diagram" else "overview"
            return RedirectResponse(
                f"/clusters?project={pid}&cluster={cid}&tab={want}"
                f"&env={urllib.parse.quote(env)}", 303)
        # no cluster assigned yet — still the cluster page (its project view), where
        # this environment's mapping is set, rather than the standalone service list
        return RedirectResponse(
            f"/clusters?project={pid}&env={urllib.parse.quote(env)}", 303)
    # every values file in the environment, in two groups: the services this
    # project puts front and centre, and everything else. Both are editable —
    # the project's naming settings decide the order, not what exists.
    groups = repo.split_services(pid, rgid, env)
    files = groups["all"]
    tab = tab or "services"
    ns = repo.namespaces(pid, rgid, env)
    pods = svg = topo = None

    if tab in ("pods", "diagram"):
        if not cluster:
            err = ("no cluster matched this environment — assign one in "
                   "Settings → Kubernetes clusters")
            pods, topo = {"pods": [], "error": err}, {"error": err}
        elif not ns:
            # namespaces are read from the values files, so an unconnected repo
            # looks identical to an empty environment. Name the real cause —
            # from THIS environment's own checkout, which is its own binding's
            # repo when it has one, not necessarily the region's.
            cloned = repo.checkout(pid, rgid, env).exists()
            err = ("no namespaces found in this environment's values files"
                   if cloned else
                   "this environment's GitOps repo is not connected yet, so "
                   "there are no values files to read namespaces from — check "
                   "its binding in Settings → Kubernetes clusters")
            pods, topo = {"pods": [], "error": err}, {"error": err}
        elif tab == "pods":
            pods = kube.get_pods(cluster, ns)
        else:
            topo = topology.collect(pid, rgid, env, cluster, ns)
            if not topo["error"]:
                svg = diagram.render(topo)

    return templates.TemplateResponse(
        request, "env.html",
        ctx(request, pid, rgid, env=env, files=files, groups=groups,
            cluster=(cluster or {}).get("name"), tab=tab,
            pods=pods, svg=svg, topo=topo, namespaces=ns))


@app.get("/p/{pid}/{rgid}/{env}/logs/{namespace}/{pod}", response_class=HTMLResponse)
def pod_logs(request: Request, pid: str, rgid: str, env: str, namespace: str,
             pod: str, container: str = "", tail: int = 300):
    cluster = store.cluster_for_env(pid, rgid, env)
    containers = logs.containers_of(cluster, namespace, pod) if cluster else []
    if not container and containers:
        container = containers[0]
    text = (logs.snapshot(cluster, namespace, pod, container, tail)
            if cluster else "no cluster assigned to this environment")
    return templates.TemplateResponse(
        request, "logs.html",
        ctx(request, pid, rgid, env=env, namespace=namespace, pod=pod,
            containers=containers, container=container, tail=tail, text=text,
            cluster=(cluster or {}).get("name")))


@app.get("/p/{pid}/{rgid}/{env}/containers/{namespace}/{pod}")
def pod_containers(pid: str, rgid: str, env: str, namespace: str, pod: str):
    cluster = store.cluster_for_env(pid, rgid, env)
    return JSONResponse(
        {"containers": logs.containers_of(cluster, namespace, pod)
         if cluster else []})


@app.get("/p/{pid}/{rgid}/{env}/logstream/{namespace}/{pod}")
def pod_logstream(pid: str, rgid: str, env: str, namespace: str, pod: str,
                  container: str = "", tail: int = 200):
    cluster = store.cluster_for_env(pid, rgid, env)
    if not cluster:
        return StreamingResponse(iter([": no cluster\n\n"]),
                                 media_type="text/event-stream")
    return StreamingResponse(
        logs.stream(cluster, namespace, pod, container, tail),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/p/{pid}/{rgid}/{env}/new", response_class=HTMLResponse)
def service_new_form(request: Request, pid: str, rgid: str, env: str,
                     err: str = ""):
    ns = repo.namespaces(pid, rgid, env)
    return templates.TemplateResponse(
        request, "new_service.html",
        ctx(request, pid, rgid, env=env, namespace=ns[0] if ns else "",
            all_files=repo.all_files(pid, rgid, env), err=err))


@app.post("/p/{pid}/{rgid}/{env}/new")
async def service_new(request: Request, pid: str, rgid: str, env: str):
    f = await request.form()
    cfg = {}
    for i in range(1, 31):
        k = str(f.get(f"ck{i}", "")).strip()
        if k:
            cfg[k] = str(f.get(f"cv{i}", "")).strip()
    try:
        if str(f.get("mode", "new")) == "existing":
            fname = str(f.get("target_file", ""))
            if not cfg:
                raise ValueError("add at least one config key")
            repo.add_config_keys(pid, rgid, env, fname, cfg)
        else:
            fname = repo.create_service(
                pid, rgid, env, name=str(f.get("name", "")),
                image_repo=str(f.get("image_repo", "")),
                image_tag=str(f.get("image_tag", "latest")),
                port=int(f.get("port", 8080) or 8080),
                namespace=str(f.get("namespace", "")), config=cfg)
    except ValueError as e:
        return RedirectResponse(
            f"/p/{pid}/{rgid}/{env}/new?err={str(e)[:200]}", 303)
    return RedirectResponse(f"/p/{pid}/{rgid}/{env}/s/{fname}?saved=created", 303)


# ── one values file, in a window ────────────────────────────────
# The file itself, read and written as text, with the two things that are only
# ever wanted here: seal a secret into it, and push it. It replaced a whole page
# — see `service_view` below for why — and these four routes are what that page
# was actually used for.
#
# They live under `/p/` so the `config` area gates them exactly like every other
# values route (rbac.AREAS), and each is a thin wrapper over the function the old
# page already called: repo.read_raw / repo.save_raw, sealing.seal_value +
# repo.save_sealed_secrets, gitrepo.commit_and_push.
def _values_where(pid: str, rgid: str, env: str, fname: str) -> dict:
    """Everything the window needs to describe the file, live off disk."""
    rel = repo.rel_path(pid, rgid, env, fname)
    meta, sealed_keys, load_err = {}, [], ""
    try:
        svc = repo.load_service(pid, rgid, env, fname)
        meta, sealed_keys = svc["meta"], svc["secret_keys"]
    except Exception as e:                                    # noqa: BLE001
        # A file too broken to model is still a file somebody must be able to
        # OPEN and fix — that is the whole reason this window edits text. The
        # structured half degrades; the text half does not.
        load_err = f"{type(e).__name__}: {str(e).splitlines()[0][:200]}"
    cluster = store.cluster_for_env(pid, rgid, env) or {}
    secret_name = (meta.get("secret_name")
                   or (f"{meta.get('name')}-secret" if meta.get("name") else ""))
    return {"rel": rel, "meta": meta, "sealed_keys": sealed_keys,
            "load_error": load_err, "cluster": cluster,
            "namespace": meta.get("namespace") or "",
            "secret_name": secret_name}


@app.get("/p/{pid}/{rgid}/{env}/s/{fname}/raw.json")
def values_raw(request: Request, pid: str, rgid: str, env: str, fname: str):
    try:
        text = repo.read_raw(pid, rgid, env, fname)
    except Exception as e:                                    # noqa: BLE001
        return JSONResponse({"error": f"{type(e).__name__}: {str(e)[:200]}"})
    w = _values_where(pid, rgid, env, fname)
    warmer.note_view("region", f"{pid}/{rgid}")
    st = git_ops.region_status(pid, rgid, check_remote=False, env=env)
    diff = git_ops.diff_file(pid, rgid, w["rel"], env=env)
    # Sealing needs a cluster to seal AGAINST (the certificate is the
    # controller's, per cluster) and a namespace + secret name to scope the
    # blob to. Each missing piece is named rather than the button being dead.
    why = ""
    if not w["cluster"]:
        why = ("no cluster serves this environment, so there is no sealing "
               "certificate to seal against — map one in Settings → Clusters")
    elif not w["namespace"] or not w["secret_name"]:
        why = ("this file does not say which namespace and secret to seal "
               "into, so a sealed value could not be scoped")
    return JSONResponse({
        "text": text, "rel": w["rel"], "branch": st["branch"],
        "modified": bool(diff.strip()), "diff": diff[:20000],
        "warnings": repo.lint(text), "load_error": w["load_error"],
        "namespace": w["namespace"], "secret_name": w["secret_name"],
        "sealed_keys": w["sealed_keys"], "seal_why": why,
        "may_seal": not why,
        "cluster": w["cluster"].get("name", ""),
        "service": repo.display(pid, fname),
        "is_prod": config.is_prod_env(env, repo.naming(pid)["aliases"]),
    })


@app.post("/p/{pid}/{rgid}/{env}/s/{fname}/raw/save")
async def values_raw_save(request: Request, pid: str, rgid: str, env: str,
                          fname: str):
    """Write the working copy. Nothing leaves the machine until commit."""
    f = await request.form()
    try:
        warnings = await run_in_threadpool(repo.save_raw, pid, rgid, env, fname,
                                          str(f.get("text", "")))
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)[:400]})
    except Exception as e:                                    # noqa: BLE001
        return JSONResponse({"ok": False,
                             "error": f"{type(e).__name__}: {str(e)[:300]}"})
    rel = repo.rel_path(pid, rgid, env, fname)
    auth.audit(getattr(request.state, "user", None), "config_edit",
               f"{(store.get_region(pid, rgid) or {}).get('name','?')}/{env}/{fname}",
               "whole file edited", _client_ip(request))
    return JSONResponse({"ok": True, "warnings": warnings,
                         "modified": bool(git_ops.diff_file(
                             pid, rgid, rel, env=env).strip())})


@app.post("/p/{pid}/{rgid}/{env}/s/{fname}/raw/seal")
async def values_raw_seal(request: Request, pid: str, rgid: str, env: str,
                          fname: str):
    """Seal one plaintext value into the file's SealedSecret block.

    The plaintext arrives, is handed to kubeseal, and is never stored, echoed
    or logged — what comes back is the encrypted blob and the key's NAME. The
    audit line records that a key was sealed, never its value.
    """
    f = await request.form()
    key = str(f.get("key", "")).strip()
    value = str(f.get("value", ""))
    if not key:
        return JSONResponse({"ok": False, "error": "name the key to seal"})
    if not value:
        return JSONResponse({"ok": False,
                             "error": "there is nothing to seal — the value is empty"})
    w = _values_where(pid, rgid, env, fname)
    if not w["cluster"]:
        return JSONResponse({"ok": False, "error": "no cluster serves this "
                             "environment, so there is no sealing certificate"})
    if not w["namespace"] or not w["secret_name"]:
        return JSONResponse({"ok": False, "error": "this file does not say which "
                             "namespace and secret to seal into"})
    try:
        blob = await run_in_threadpool(
            sealing.seal_value, pid, w["cluster"], w["namespace"],
            w["secret_name"], value)
        await run_in_threadpool(repo.save_sealed_secrets, pid, rgid, env, fname,
                                {key: blob})
    except sealing.SealingError as e:
        return JSONResponse({"ok": False, "error": str(e)[:400]})
    except Exception as e:                                    # noqa: BLE001
        return JSONResponse({"ok": False,
                             "error": f"{type(e).__name__}: {str(e)[:300]}"})
    auth.audit(getattr(request.state, "user", None), "secret_sealed",
               f"{(store.get_region(pid, rgid) or {}).get('name','?')}/{env}/{fname}",
               f"{key} → {w['namespace']}/{w['secret_name']}", _client_ip(request))
    rotated = key in w["sealed_keys"]
    return JSONResponse({
        "ok": True, "key": key, "rotated": rotated,
        "text": repo.read_raw(pid, rgid, env, fname),
        "sealed_keys": _values_where(pid, rgid, env, fname)["sealed_keys"],
        "scope": f"{w['namespace']}/{w['secret_name']}"})


@app.post("/p/{pid}/{rgid}/{env}/s/{fname}/raw/commit")
async def values_raw_commit(request: Request, pid: str, rgid: str, env: str,
                            fname: str):
    """Commit and push this one file. Same path the old page's button used."""
    f = await request.form()
    rg = store.get_region(pid, rgid) or {}
    rel = repo.rel_path(pid, rgid, env, fname)
    me = getattr(request.state, "user", None) or {}
    message = str(f.get("message", "")).strip()
    if not message:
        return JSONResponse({"ok": False, "error": "write a commit message"})
    conf = gitrepo.env_repo(pid, rgid, env)
    try:
        result = await run_in_threadpool(
            gitrepo.commit_and_push, pid, rgid, conf, [rel], message=message,
            new_branch=str(f.get("new_branch", "")).strip(),
            author=auth.git_author(me), env_name=env)
    except gitrepo.GitError as e:
        auth.audit(me, "commit_failed", f"{rg.get('name','?')}/{env}/{fname}",
                   str(e), _client_ip(request))
        return JSONResponse({"ok": False, "error": str(e)[:400]})
    auth.audit(me, "commit_push", f"{rg.get('name','?')}/{env}/{fname}",
               f"{result['sha']} → {result['branch']}", _client_ip(request))
    return JSONResponse({
        "ok": True, "sha": result["sha"], "branch": result["branch"],
        "noop": bool(result.get("noop")),
        "link": gitrepo.commit_url(conf.get("url", ""), result["sha"]),
        "modified": bool(git_ops.diff_file(pid, rgid, rel, env=env).strip())})


@app.post("/p/{pid}/{rgid}/{env}/s/{fname}/raw/discard")
async def values_raw_discard(request: Request, pid: str, rgid: str, env: str,
                             fname: str):
    """Throw the working-copy edits away and read git's version again."""
    rel = repo.rel_path(pid, rgid, env, fname)
    await run_in_threadpool(git_ops.discard_file, pid, rgid, rel, env=env)
    auth.audit(getattr(request.state, "user", None), "config_discard",
               f"{(store.get_region(pid, rgid) or {}).get('name','?')}/{env}/{fname}",
               "uncommitted edits discarded", _client_ip(request))
    return JSONResponse({"ok": True,
                         "text": repo.read_raw(pid, rgid, env, fname)})


@app.get("/p/{pid}/{rgid}/{env}/s/{fname}", response_class=HTMLResponse)
def service_view(pid: str, rgid: str, env: str, fname: str,
                 saved: str = "", error: str = "", commit: str = ""):
    """The service page is gone — open the file in a window instead.

    It was a two-column page (what git declares beside what the cluster is
    running) with a structured editor per key. Retired on request: reaching it
    cost you the list you were reading, and the three things it was used for —
    read the file, change a value, push it — now live in `_values_dialog.html`,
    over whichever list you opened it from.

    This route SURVIVES AS A REDIRECT rather than being deleted, because the URL
    is linked from six other places: portal search results (three kinds of hit),
    the Compare page's per-environment columns, the assistant's answers, the
    GitOps app page's "Edit in git" button, the environment page's tiles, and
    the service `service_new` has just created. Deleting the route would have
    turned every one of those into a 404, found one at a time by whoever
    clicked.

    It lands on the page that HOSTS the window — the serving cluster's GitOps
    repo tab, or the environment's own page when no cluster is mapped — carrying
    the four identifiers the dialog needs to open itself.
    """
    q = urllib.parse.urlencode({"vpid": pid, "vrgid": rgid, "venv": env,
                                "vfile": fname})
    cluster = store.cluster_for_env(pid, rgid, env)
    if cluster:
        return RedirectResponse(
            f"/clusters?project={urllib.parse.quote(pid)}"
            f"&cluster={urllib.parse.quote(cluster['id'])}&tab=config&{q}", 303)
    # No cluster serves this environment, so the cluster page has no block for
    # it. The environment's own page lists the same files and hosts the same
    # window.
    return RedirectResponse(
        f"/p/{urllib.parse.quote(pid)}/{urllib.parse.quote(rgid)}"
        f"/{urllib.parse.quote(env)}?tab=services&{q}", 303)


# ── authentication ─────────────────────────────────────────────
def _client_ip(request: Request) -> str:
    return (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else ""))


@app.get("/bootstrap", response_class=HTMLResponse)
def bootstrap_form(request: Request, err: str = ""):
    if auth.any_users():
        return RedirectResponse("/login", 303)
    return templates.TemplateResponse(
        request, "bootstrap.html", {"request": request, "status": None, "err": err})


@app.post("/bootstrap")
async def bootstrap(request: Request):
    if auth.any_users():
        return RedirectResponse("/login", 303)
    f = await request.form()
    email = str(f.get("email", "")).strip().lower()
    name = str(f.get("name", "")).strip()
    pw, pw2 = str(f.get("password", "")), str(f.get("password2", ""))
    if "@" not in email:
        return RedirectResponse("/bootstrap?err=enter a valid email address", 303)
    if pw != pw2:
        return RedirectResponse("/bootstrap?err=passwords do not match", 303)
    if (problem := auth.password_problem(pw)):
        return RedirectResponse(f"/bootstrap?err={problem}", 303)
    uid = auth.create_user(email, name, pw, role="admin")
    auth.audit({"email": email}, "bootstrap_admin", email, ip=_client_ip(request))
    request.session.update({"uid": uid, "mfa_ok": False})
    return RedirectResponse("/mfa/setup", 303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, err: str = "", next: str = "/"):
    if not auth.any_users():
        return RedirectResponse("/bootstrap", 303)
    return templates.TemplateResponse(
        request, "login.html", {"request": request, "status": None, "err": err,
                       "next": next, "microsoft": sso.ready()})


@app.post("/login")
async def login(request: Request):
    f = await request.form()
    email = str(f.get("email", "")).strip().lower()
    pw = str(f.get("password", ""))
    nxt = str(f.get("next", "/")) or "/"
    u = auth.by_email(email)
    ip = _client_ip(request)
    if not u or u.get("disabled") or not auth.verify_password(u["password"], pw):
        auth.audit({"email": email or "?"}, "login_failed", email, ip=ip)
        return RedirectResponse("/login?err=invalid email or password", 303)
    request.session.update({"uid": u["id"], "mfa_ok": False, "next": nxt})
    if not u.get("mfa_enrolled"):
        return RedirectResponse("/mfa/setup", 303)
    return RedirectResponse("/mfa", 303)


# ── sign in with Microsoft ─────────────────────────────────────
def _sso_redirect_uri(request: Request) -> str:
    """The callback URL Microsoft must send the browser back to. Derived from
    the request so it is right on a laptop and behind an ingress alike —
    provided the proxy sets X-Forwarded-Proto/Host and uvicorn is told to trust
    it. When that is not true, the admin sets the exact URL in the settings
    card instead, because Entra compares it character for character."""
    override = sso.config()["redirect_override"]
    if override:
        return override
    return str(request.base_url).rstrip("/") + "/auth/microsoft/callback"


@app.get("/login/microsoft")
def login_microsoft(request: Request, next: str = "/"):
    if not sso.ready():
        return RedirectResponse("/login?err=Microsoft sign-in is not configured", 303)
    url, state, nonce = sso.begin(_sso_redirect_uri(request))
    request.session.update({"sso_state": state, "sso_nonce": nonce,
                            "sso_next": next if next.startswith("/") else "/"})
    return RedirectResponse(url, 303)


@app.get("/auth/microsoft/callback")
def microsoft_callback(request: Request, code: str = "", state: str = "",
                       error: str = "", error_description: str = ""):
    if not sso.ready():
        return RedirectResponse("/login", 303)
    ip = _client_ip(request)
    if error:
        # the person cancelled, or Entra refused — their story, told briefly
        detail = (error_description or error).split(".")[0][:160]
        return RedirectResponse(f"/login?err={urllib.parse.quote(detail)}", 303)
    want = request.session.pop("sso_state", "")
    nonce = request.session.pop("sso_nonce", "")
    nxt = request.session.pop("sso_next", "/") or "/"
    if not code or not want or state != want:
        return RedirectResponse(
            "/login?err=the sign-in did not start here — please try again", 303)
    try:
        who = sso.complete(code, _sso_redirect_uri(request), nonce)
    except sso.SsoError as e:
        auth.audit(None, "login_microsoft_failed", detail=str(e), ip=ip)
        return RedirectResponse(f"/login?err={urllib.parse.quote(str(e))}", 303)

    u = auth.by_email(who["email"])
    if u and u.get("disabled"):
        auth.audit(u, "login_microsoft_denied", who["email"],
                   "account disabled", ip)
        return RedirectResponse("/login?err=this account is disabled", 303)
    if not u:
        if not sso.config()["auto_create"]:
            auth.audit(None, "login_microsoft_denied", who["email"],
                       "no portal account and auto-create is off", ip)
            return RedirectResponse(
                "/login?err=" + urllib.parse.quote(f"{who['email']} has no account here — "
                                      "ask an admin to add you"), 303)
        uid = auth.create_sso_user(who["email"], who["name"])
        u = auth.by_id(uid)
        auth.audit(u, "user_autocreated_microsoft", who["email"], ip=ip)

    # Entra has already applied the organisation's MFA policy, so the local
    # TOTP step is not asked for on top of it
    request.session.update({"uid": u["id"], "mfa_ok": True})
    auth.update_user(u["id"], last_login=time.strftime("%Y-%m-%d %H:%M:%S"))
    auth.audit(u, "login_microsoft", ip=ip)
    return RedirectResponse(nxt if nxt.startswith("/") else "/", 303)


@app.get("/mfa/setup", response_class=HTMLResponse)
def mfa_setup(request: Request, err: str = ""):
    uid = request.session.get("uid")
    u = auth.by_id(uid) if uid else None
    if not u:
        return RedirectResponse("/login", 303)
    if u.get("mfa_enrolled") and request.session.get("mfa_ok"):
        return RedirectResponse("/", 303)
    secret = u.get("totp_secret") or auth.begin_mfa_enrolment(uid)
    qr_src, qr_px = auth.totp_qr(auth.totp_uri(u["email"], secret))
    return templates.TemplateResponse(
        request, "mfa_setup.html",
        {"request": request, "status": None, "err": err, "me": u,
         "secret": secret, "qr_src": qr_src, "qr_px": qr_px})


@app.post("/mfa/setup")
async def mfa_setup_confirm(request: Request):
    f = await request.form()
    uid = request.session.get("uid")
    if not uid:
        return RedirectResponse("/login", 303)
    if auth.confirm_mfa(uid, str(f.get("code", ""))):
        request.session["mfa_ok"] = True
        auth.update_user(uid, last_login=time.strftime("%Y-%m-%d %H:%M:%S"))
        auth.audit(auth.by_id(uid), "mfa_enrolled", ip=_client_ip(request))
        return RedirectResponse(request.session.pop("next", "/") or "/", 303)
    return RedirectResponse("/mfa/setup?err=that code did not match — try the next one", 303)


@app.get("/mfa", response_class=HTMLResponse)
def mfa_form(request: Request, err: str = ""):
    uid = request.session.get("uid")
    u = auth.by_id(uid) if uid else None
    if not u:
        return RedirectResponse("/login", 303)
    if not u.get("mfa_enrolled"):
        return RedirectResponse("/mfa/setup", 303)
    return templates.TemplateResponse(
        request, "mfa.html", {"request": request, "status": None, "err": err, "me": u})


@app.post("/mfa")
async def mfa_verify(request: Request):
    f = await request.form()
    uid = request.session.get("uid")
    u = auth.by_id(uid) if uid else None
    ip = _client_ip(request)
    if not u:
        return RedirectResponse("/login", 303)
    if auth.verify_totp(u.get("totp_secret", ""), str(f.get("code", ""))):
        request.session["mfa_ok"] = True
        auth.update_user(uid, last_login=time.strftime("%Y-%m-%d %H:%M:%S"))
        auth.audit(u, "login", ip=ip)
        return RedirectResponse(request.session.pop("next", "/") or "/", 303)
    auth.audit(u, "mfa_failed", ip=ip)
    return RedirectResponse("/mfa?err=incorrect code", 303)


# ── passkeys: sign in with a fingerprint, a face, or a security key ──
#
# The login half lives under /login/ and the management half under /me/ so each
# inherits the gate it needs from OPEN_PATHS —
# no third list of exceptions to keep in step, and /me is already reachable
# when an ended trial has locked everything else, which is right: your own
# sign-in credentials are not the thing to hold hostage.
def _pk_base(request: Request) -> str:
    return str(request.base_url).rstrip("/")


@app.post("/login/passkey/options")
async def passkey_login_options(request: Request):
    """A challenge to sign. No session yet, by definition."""
    f = await request.form()
    try:
        return Response(
            passkeys.login_options(_pk_base(request), request.session,
                                   email=str(f.get("email", ""))),
            media_type="application/json")
    except Exception as e:                                    # noqa: BLE001
        return JSONResponse({"error": str(e)[:300]}, status_code=400)


@app.post("/login/passkey/verify")
async def passkey_login_verify(request: Request):
    """A signed challenge. On success this is a COMPLETE sign-in.

    `mfa_ok` is set here, and that is the point of the feature rather than a
    shortcut: a platform passkey is the device plus the person the device
    verified, which is the same two factors the password and the code are. The
    module refuses to register or accept one without user verification, so the
    claim holds.
    """
    ip = _client_ip(request)
    try:
        body = await request.json()
        row = await run_in_threadpool(
            passkeys.verify_login, body, _pk_base(request), request.session)
    except Exception as e:                                    # noqa: BLE001
        auth.audit({"email": "?"}, "passkey_failed", "", str(e)[:200], ip)
        return JSONResponse({"error": str(e)[:300]}, status_code=400)
    u = auth.by_id(row["uid"])
    if not u or u.get("disabled"):
        # A disabled account keeps its passkeys; the door is what closed.
        auth.audit({"email": row["uid"]}, "passkey_failed", row["uid"],
                   "account disabled or gone", ip)
        return JSONResponse({"error": "this account cannot sign in"},
                            status_code=403)
    nxt = request.session.get("next", "/") or "/"
    request.session.update({"uid": u["id"], "mfa_ok": True})
    request.session.pop("next", None)
    auth.update_user(u["id"], last_login=time.strftime("%Y-%m-%d %H:%M:%S"))
    auth.audit(u, "login", "passkey", row.get("name", ""), ip)
    return JSONResponse({"ok": True, "next": nxt})


@app.post("/me/passkey/options")
async def passkey_register_options(request: Request):
    me = current_user(request)
    if not me:
        return JSONResponse({"error": "sign in first"}, status_code=403)
    try:
        return Response(
            passkeys.register_options(me, _pk_base(request), request.session),
            media_type="application/json")
    except Exception as e:                                    # noqa: BLE001
        return JSONResponse({"error": str(e)[:300]}, status_code=400)


@app.post("/me/passkey/verify")
async def passkey_register_verify(request: Request):
    me = current_user(request)
    if not me:
        return JSONResponse({"error": "sign in first"}, status_code=403)
    try:
        body = await request.json()
        got = await run_in_threadpool(
            passkeys.verify_registration, me, body.get("credential"),
            _pk_base(request), request.session,
            # Named from the browser that made it, not from a box somebody has
            # to fill in. "MacBook · Safari" is what you need to recognise it
            # in a list months later, and asking for it is one more field
            # between a person and the thing they came to do.
            passkeys.device_name(request.headers.get("user-agent", "")))
    except Exception as e:                                    # noqa: BLE001
        return JSONResponse({"error": str(e)[:300]}, status_code=400)
    auth.audit(me, "passkey_added", got["name"], got["id"],
               _client_ip(request))
    return JSONResponse({"ok": True, **got})


@app.post("/me/passkey/{pid}/delete")
async def passkey_delete(request: Request, pid: str):
    me = current_user(request)
    if not me:
        return RedirectResponse("/login", 303)
    # Removing one is not destroying anything reachable — the password and the
    # authenticator app still sign this account in — so it is an operational
    # confirm in the template, not the typed-Delete gesture.
    if passkeys.drop(me["id"], pid):
        auth.audit(me, "passkey_removed", pid, ip=_client_ip(request))
    return RedirectResponse("/me#passkeys", 303)


@app.get("/logout")
def logout(request: Request):
    u = auth.by_id(request.session.get("uid", ""))
    if u:
        auth.audit(u, "logout", ip=_client_ip(request))
    request.session.clear()
    return RedirectResponse("/login", 303)


# ── users (admin) ──────────────────────────────────────────────
def _admin(request: Request):
    u = getattr(request.state, "user", None)
    return u if u and u.get("role") == "admin" else None


def _may(request: Request, area: str):
    """The user, if their roles include this area. Administrators always do.

    Lets the Administration pages be delegated one at a time instead of only
    as "make them an administrator", which was the whole of the choice before.
    """
    u = getattr(request.state, "user", None)
    return u if u and rbac.may_area(u, area) else None


def _guard_user_edit(me: dict, target: dict | None, want_admin: bool,
                     role_ids) -> str:
    """Why this account change is refused, or "" if it is allowed.

    Somebody who manages users but is not an administrator must not be able to
    become one. There are three doors and all three need closing: making the
    account an administrator outright, editing an account that already is one,
    and handing over a role that carries Settings, User accounts or Cluster
    management — each of which leads back to the first two.
    """
    if rbac.is_admin(me):
        return ""
    if want_admin:
        return ("only an administrator can make somebody an administrator")
    if target and target.get("role") == "admin":
        return "only an administrator can change an administrator's account"
    for rid in role_ids or ():
        role = rbac.get(rid)
        if role and rbac.escalating(role):
            names = ", ".join(sorted(rbac.ESCALATING & set(role["areas"])))
            return (f"“{role['name']}” grants {names}, which only an "
                    f"administrator can hand out")
    return ""


# ── the assistant ──────────────────────────────────────────────
@app.get("/assistant")
def assistant_page():
    """The assistant is a panel in the corner of every page, not a page of its
    own — a question about the estate is something you have while looking at
    something else. This keeps old links working by opening the panel."""
    return RedirectResponse("/?assistant=1", 303)


@app.post("/assistant/query")
def assistant_query(request: Request, body: dict = Body(...)):
    """Answer a question by running a real query against live state.

    This returns the table, and it returns it fast — no model is involved, so an
    unconfigured portal answers just as well as a configured one. The optional
    prose comes afterwards from /assistant/summarise, which is handed these rows
    rather than the whole estate.
    """
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "assistant"):
        return JSONResponse({"error": "your roles do not include the assistant"},
                            status_code=403)
    question = str(body.get("question", ""))[:2000].strip()
    if not question:
        return JSONResponse({"error": "ask something first"}, status_code=400)

    started = time.time()
    # the last exchange, so a follow-up can inherit its subject
    prev = body.get("previous") if isinstance(body.get("previous"), dict) else None
    name, conf, how = assistant.route(me, question, prev)
    # A continued question keeps the previous subject explicitly rather than by
    # re-reading its words: "give me the one for za preprod" inherits focus
    # "traefik" and the new cluster, and if that cluster has no traefik the
    # answer says so instead of substituting different rows.
    effective, focus = question, ""
    if prev and how.startswith("continuing"):
        effective = f"{question} {prev.get('question', '')}".strip()
        focus = str(prev.get("focus", ""))[:60]
    # "...on the same cluster" changes subject but keeps the scope. Without this
    # the new query silently widened to every cluster, which reads as an answer
    # about the wrong thing rather than as a missing one.
    inherit = assistant.inherited_cluster(question, prev)
    if inherit and inherit.lower() not in effective.lower():
        effective = f"{effective} {inherit}".strip()
    caps = answers.capabilities(me)
    if not name:
        return JSONResponse({
            "matched": False, "question": question,
            "capabilities": caps,
            "message": "I could not tell which data would answer that. These are "
                       "the things I can look up:"})
    try:
        got = answers.run(me, name, effective, focus)
    except PermissionError as e:
        return JSONResponse({"error": f"your roles do not include {e}"},
                            status_code=403)
    except Exception as e:                                    # noqa: BLE001
        return JSONResponse({"error": f"{type(e).__name__}: {e}"},
                            status_code=500)
    took = round(time.time() - started, 2)
    auth.audit(me, "assistant_query", question[:120],
               f"{got['query']} · {got['count']} rows · {took}s · {how}",
               _client_ip(request))
    CAP = 300      # a browser table, not an export
    return JSONResponse({
        "matched": True, "question": question, "effective": effective,
        "focus": got.get("focus", ""), "query": got["query"],
        # echoed back so the next question can say "the same cluster"
        "cluster_phrase": (answers.find_cluster(effective)[1] or
                           (prev or {}).get("cluster_phrase", "") if prev
                           else answers.find_cluster(effective)[1]),
        # written by code from the rows: instant, identical every time, and
        # available with no model configured at all
        "headline": answers.headline(got),
        "label": got["label"], "note": got["note"], "how": how,
        "confidence": round(conf, 2), "columns": got["columns"],
        "rows": got["rows"][:CAP], "count": got["count"],
        "truncated": got["count"] > CAP, "seconds": took,
        "can_summarise": assistant.ready(),
        "capabilities": caps})


@app.post("/assistant/summarise")
async def assistant_summarise(request: Request):
    """A few sentences about the rows the portal just fetched, streamed."""
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "assistant"):
        return JSONResponse({"error": "your roles do not include the assistant"},
                            status_code=403)
    body = await request.json()
    question = str(body.get("question", ""))[:2000]
    name = str(body.get("query", ""))
    focus = str(body.get("focus", ""))[:60]
    if name not in answers.CATALOGUE:
        return JSONResponse({"error": "unknown query"}, status_code=400)
    try:
        got = answers.run(me, name, question, focus)
    except PermissionError as e:
        return JSONResponse({"error": f"your roles do not include {e}"},
                            status_code=403)
    result_text = answers.as_text(got)

    def frames():
        try:
            for piece in assistant.summarise_stream(
                    me, question, result_text, len(got["rows"])):
                yield f"data: {json.dumps({'text': piece})}\n\n"
        except assistant.AiError as e:
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
        except Exception as e:                                # noqa: BLE001
            yield ("event: error\ndata: "
                   + json.dumps({"error": f"{type(e).__name__}: {e}"}) + "\n\n")
        else:
            yield "event: done\ndata: {}\n\n"

    return StreamingResponse(
        frames(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/assistant/stream")
async def assistant_stream(request: Request):
    """The answer as it is generated, over server-sent events.

    Streaming rather than one late reply: even a fast model is several seconds,
    and a silent "thinking…" bubble is indistinguishable from a hang — which is
    precisely how this felt before. The generator is synchronous and blocks on
    the network, so Starlette runs it in a threadpool; the event loop stays free.
    """
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "assistant"):
        return JSONResponse({"error": "your roles do not include the assistant"},
                            status_code=403)
    body = await request.json()
    turns = [{"role": ("assistant" if str(t.get("role")) == "assistant" else "user"),
              "text": str(t.get("text", ""))[:6000]}
             for t in (body.get("turns") or [])][-assistant.HISTORY:]
    if not turns:
        return JSONResponse({"error": "ask something first"}, status_code=400)

    question = turns[-1]["text"]
    ip = _client_ip(request)

    def frames():
        sent = 0
        try:
            for kind, payload in assistant.stream(me, turns):
                if kind == "meta":
                    yield f"event: meta\ndata: {json.dumps(payload)}\n\n"
                else:
                    sent += len(payload)
                    yield f"data: {json.dumps({'text': payload})}\n\n"
        except assistant.AiError as e:
            yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
        except Exception as e:                                # noqa: BLE001
            yield ("event: error\ndata: "
                   + json.dumps({"error": f"{type(e).__name__}: {e}"}) + "\n\n")
        else:
            yield "event: done\ndata: {}\n\n"
        finally:
            # audited once the exchange is over, with how much came back, so a
            # stream that died halfway is distinguishable from one that never
            # started. The question is recorded; the answer deliberately is not.
            auth.audit(me, "assistant_asked", question[:120],
                       f"{sent} characters returned", ip)

    return StreamingResponse(
        frames(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/settings/assistant", response_class=HTMLResponse)
def settings_assistant(request: Request, msg: str = "", err: str = ""):
    if not _admin(request):
        return templates.TemplateResponse(request, "denied.html", ctx(request),
                                          status_code=403)
    return templates.TemplateResponse(
        request, "set_assistant.html",
        ctx(request, cfg=assistant.config(), providers=assistant.PROVIDERS,
            provider_notes={k: v["note"]
                            for k, v in assistant.PROVIDERS.items()},
            provider_hints={k: v["url_hint"]
                            for k, v in assistant.PROVIDERS.items()},
            provider_models={k: v["model_hint"]
                             for k, v in assistant.PROVIDERS.items()},
            sample=assistant.briefing(getattr(request.state, "user", None)),
            msg=msg, err=err))


@app.post("/settings/assistant")
async def settings_assistant_save(request: Request):
    me = _admin(request)
    if not me:
        return RedirectResponse("/settings/assistant?err=admins only", 303)
    f = await request.form()
    provider = str(f.get("provider", "")).strip()
    enabled = bool(f.get("enabled"))
    if enabled and provider not in assistant.PROVIDERS:
        return back(err="choose a provider", to="/settings/assistant")
    assistant.save(enabled=enabled, provider=provider,
                   base_url=str(f.get("base_url", "")).strip().rstrip("/"),
                   model=str(f.get("model", "")).strip(),
                   token=str(f.get("token", "")),
                   skip_tls=bool(f.get("skip_tls")))
    auth.audit(me, "assistant_configured",
               f"{provider} · {'on' if enabled else 'off'}",
               ip=_client_ip(request))
    if f.get("do_test"):
        ok, detail = await run_in_threadpool(assistant.test)
        return (back(msg=detail, to="/settings/assistant") if ok
                else back(err=detail, to="/settings/assistant"))
    return back(msg="saved", to="/settings/assistant")


# ── GitOps, Workflows, Server hardware, Hypervisors: the pages ──
@app.get("/gitops", response_class=HTMLResponse)
def gitops_page(request: Request, conn: str = "", state: str = "", q: str = "",
                project: str = "", refresh: str = ""):
    if refresh:
        gitops.invalidate()
    conns = store.all_gitops()

    def one(c):
        try:
            return {"conn": c, "rows": gitops.apps(c, refresh=bool(refresh)),
                    "error": ""}
        except Exception as e:                                # noqa: BLE001
            return {"conn": c, "rows": [], "error": str(e)[:200]}
    got, pending = gather.across("gitops", conns, one, refresh=bool(refresh))
    broken = [{"id": g["conn"]["id"], "name": g["conn"].get("name", ""),
               "error": g["error"]} for g in got if g["error"]]
    rows, needle = [], q.strip().lower()
    # Argo CD's own AppProject, not one of this portal's projects — the two
    # words collide and the select says which is meant. Collected from whatever
    # the controller filter leaves in scope, so switching controller cannot
    # leave an option behind that now matches nothing.
    in_scope = [a for g in got if not (conn and g["conn"]["id"] != conn)
                for a in g["rows"]]
    projects = sorted({(a.get("project") or "").strip()
                       for a in in_scope if (a.get("project") or "").strip()})
    for g in got:
        if conn and g["conn"]["id"] != conn:
            continue
        for a in g["rows"]:
            if project and (a.get("project") or "") != project:
                continue
            if state == "outofsync" and a["sync"] == "Synced":
                continue
            if state == "degraded" and a["health"] == "Healthy":
                continue
            if state == "ok" and not (a["sync"] == "Synced"
                                      and a["health"] == "Healthy"):
                continue
            if needle and needle not in " ".join(
                    [a["name"], a["project"], a["repo"], a["path"],
                     a["dest"]]).lower():
                continue
            rows.append({**a, "conn_name": g["conn"]["name"]})
    rows.sort(key=lambda a: (a["health"] == "Healthy" and a["sync"] == "Synced",
                             a["name"]))
    everything = [a for g in got for a in g["rows"]]
    # One controller per card, with its own counts, and no controller chosen
    # means the chooser rather than a flattened list of everything. With two
    # Argo CDs and the same application name in both, a single list cannot say
    # which one a row belongs to without the reader doing the work.
    controllers = [{
        "conn": g["conn"], "error": g["error"],
        "provider": gitops.PROVIDERS.get(g["conn"].get("type"), {}),
        "roll": gitops.summarise(g["rows"]),
    } for g in got]
    # Argo CD's own settings — repositories, clusters, projects — for the rail.
    # One SWR entry, and a controller that refuses one of the three still gets a
    # rail: settings_view degrades per endpoint rather than as a whole.
    argo = {}
    if conn and any(c["conn"]["id"] == conn and not c["error"]
                    for c in controllers):
        try:
            argo = gitops.settings_view(_gitops_conn(conn) or {})
        except gitops.GitOpsError:
            argo = {}
    return templates.TemplateResponse(
        request, "gitops.html",
        ctx(request, conns=conns, rows=rows, broken=broken, argo=argo,
            pending=pending, controllers=controllers,
            chosen=next((c for c in controllers
                         if c["conn"]["id"] == conn), None),
            total=len(everything), roll=gitops.summarise(everything),
            want_conn=conn, state=state, q=q,
            projects=projects, want_project=project))


def _gitops_conn(cid: str) -> dict | None:
    return next((c for c in store.all_gitops() if c.get("id") == cid), None)


@app.get("/gitops/app", response_class=HTMLResponse)
def gitops_app(request: Request, conn: str, name: str, msg: str = "",
               err: str = ""):
    """One application, the way Argo CD shows it: what it is, what it is made
    of, and what happened to it."""
    c = _gitops_conn(conn)
    if not c:
        return RedirectResponse("/gitops?err=that+controller+is+gone", 303)
    detail = resources = past = None
    op = None
    events, parms = [], {}
    rev_meta, op_meta = {}, {}
    error = ""
    try:
        # two round-trips, together: the application document (which carries
        # the operation AND the history) and the resource tree — sequential,
        # these were most of the page's wait on a far-away Argo
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=3) as pool:
            f_app = pool.submit(gitops.app_view, c, name)
            f_tree = pool.submit(gitops.tree, c, name)
            f_ev = pool.submit(gitops.app_events, c, name)
        detail, op, past = f_app.result()
        resources = f_tree.result()
        # the application's own events, and what its source is rendered with —
        # both things Argo CD shows and this page did not. params() reads the
        # document app_view just cached, so it costs nothing.
        events = f_ev.result()
        parms = gitops.app_params(c, name)
        # who wrote the commit each card points at, and what they said — the
        # author/comment lines Argo CD shows on Sync Status and Last Sync
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_rt = pool.submit(gitops.revision_meta, c, name,
                               (detail or {}).get("revision", ""))
            f_ro = pool.submit(gitops.revision_meta, c, name,
                               (op or {}).get("revision", ""))
        rev_meta, op_meta = f_rt.result(), f_ro.result()
    except gitops.GitOpsError as e:
        error = str(e)
    except Exception as e:                                    # noqa: BLE001
        error = f"{type(e).__name__}: {e}"
    return templates.TemplateResponse(
        request, "gitops_app.html",
        ctx(request, conn=c, provider=gitops.PROVIDERS.get(c.get("type"), {}),
            app=detail, tree=resources or {"roots": [], "count": 0,
                                           "by_health": {}},
            graph=gitops.graph(resources or {}, (detail or {}).get("name", ""),
                               (detail or {}).get("health", ""),
                               (detail or {}).get("sync", "")),
            history=past or [], op=op, op_error="", app_events=events,
            parms=parms, rev_meta=rev_meta, op_meta=op_meta,
            sync_flags=gitops.SYNC_FLAGS, prune_policies=gitops.PRUNE_POLICIES,
            msg=msg, err=err or error))


def _git_editor_for(repo_url: str, path: str) -> dict | None:
    """Where an Argo application's SOURCE lives inside this portal, when it
    does: the registered region repo whose URL matches the app's repoURL, the
    environment whose name appears in the app's source path, and — when one
    values file's rel path carries the path's last segment — the service
    editor itself. None when the repo is not registered here, and the page
    says so instead of pretending git can be edited from this portal."""
    want = (repo_url or "").rstrip("/").lower()
    want = want[:-4] if want.endswith(".git") else want
    if not want:
        return None
    segs = (path or "").strip("/").split("/") if path else []
    tail = segs[-1] if segs else ""
    for pid, p in store.projects().items():
        for rgid, rg in (p.get("regions") or {}).items():
            envs = repo.list_envs(pid, rgid, include_hidden=True)
            matching = []
            for e in envs:
                have = (repo.binding(pid, rgid, e)["url"] or "").rstrip("/").lower()
                have = have[:-4] if have.endswith(".git") else have
                if have and have == want:
                    matching.append(e)
            if not matching:
                continue
            # prefer the matching environment the path names; a single
            # match needs no naming — its binding IS the answer
            env = next((e for e in matching if e in segs),
                       matching[0] if len(matching) == 1 else "")
            label = f"{p.get('name', pid)} · {rg.get('name', rgid)}"
            if env and tail:
                for fn in envs.get(env, []):
                    rel = fn.replace("~", "/")
                    parts = rel.split("/")
                    if tail in parts or parts[-1].startswith(tail):
                        return {"url": f"/p/{pid}/{rgid}/{env}/s/"
                                       f"{urllib.parse.quote(fn)}",
                                "label": f"{label} · {env}"}
            if env:
                return {"url": f"/p/{pid}/{rgid}/{env}",
                        "label": f"{label} · {env}"}
            return {"url": f"/p/{pid}", "label": label}
    return None


@app.get("/gitops/app/resource", response_class=HTMLResponse)
def gitops_resource(request: Request, conn: str, name: str, uid: str = "",
                    tab: str = "", container: str = "", rkind: str = "",
                    rname: str = "", rns: str = "", rgroup: str = "",
                    rversion: str = "", bare: str = "", arepo: str = "",
                    apath: str = ""):
    """One node of the resource tree, opened in place.

    A tree you cannot open is a picture. This is the manifest, what git wants
    instead if they differ, what has happened to it, and — for a pod — what it
    is saying, which are the only questions a red dot ever raises.

    Addressed by `uid` from the tree, OR by kind/name/namespace (`r*` params)
    from the sync-result table — whose rows list what an operation touched,
    including objects the tree no longer holds.
    """
    c = _gitops_conn(conn)
    if not c:
        return HTMLResponse("", status_code=409)
    try:
        resources = gitops.tree(c, name)
        if uid:
            node = gitops.find_node(resources, uid)
        elif rkind and rname:
            node = gitops.find_by_ref(resources, rkind, rname, rns,
                                      rgroup, rversion)
            uid = node.get("uid") or ""
        else:
            node = None
        if not node:
            return HTMLResponse(
                '<div class="flash err">⚠ that resource is no longer in the '
                'tree — refresh the application</div>')
        if container:
            node = {**node, "container": container}
        # the panel's data and what Argo can DO to the object, together
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_res = pool.submit(gitops.resource, c, name, node, tab)
            f_act = pool.submit(gitops.resource_actions, c, name, node)
        got = f_res.result()
        got["actions"] = f_act.result()
        got["uid"] = node.get("uid", "")
    except Exception as e:                                    # noqa: BLE001
        return templates.TemplateResponse(
            request, "gitops_res.html",
            ctx(request, res=None, res_error=str(e)[:240], conn=c,
                app_name=name, uid=uid, lines=gitops.LOG_LINES,
                bare=bool(bare), gitedit=None))
    return templates.TemplateResponse(
        request, "gitops_res.html",
        ctx(request, res=got, res_error="", conn=c, app_name=name, uid=uid,
            lines=gitops.LOG_LINES, bare=bool(bare),
            # the durable-fix option: this app's source, opened in the
            # portal's own config editor when its repo is registered here
            gitedit=_git_editor_for(arepo, apath)))


@app.post("/gitops/app/resource/edit")
async def gitops_resource_edit(request: Request, conn: str, name: str):
    """Apply an edited manifest to one live resource, through Argo CD.

    Gated like sync — the other action here that changes a cluster: a typed
    word ("apply"), audited before the call with the outcome after it. The
    patch goes through the Argo connection's own account, so its RBAC is the
    authority and Argo sees the change it is about to reconcile."""
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    f = await request.form()
    to = f"/gitops/app?conn={conn}&name={urllib.parse.quote(name)}"
    if str(f.get("confirm", "")).strip().casefold() != "apply":
        return back(err="Type apply to change the live object.", to=to)
    node = {"kind": str(f.get("rkind", "")), "name": str(f.get("rname", "")),
            "namespace": str(f.get("rns", "")),
            "group": str(f.get("rgroup", "")),
            "version": str(f.get("rversion", ""))}
    what = f"{node['kind']}/{node['name']}"
    auth.audit(request.state.user, "gitops_edit",
               f"{c.get('name', conn)}:{name}", what, _client_ip(request))
    try:
        note = gitops.patch_resource(c, name, node, str(f.get("text", "")))
    except gitops.GitOpsError as e:
        auth.audit(request.state.user, "gitops_edit_failed",
                   f"{c.get('name', conn)}:{name}", str(e)[:180],
                   _client_ip(request))
        return back(err=str(e)[:220], to=to)
    return back(msg=note, to=to)


@app.get("/gitops/app/log", response_class=PlainTextResponse)
def gitops_pod_log(request: Request, conn: str, name: str, uid: str,
                   container: str = ""):
    """Just the text of a pod's log, for the follow poll and the download.

    Its own endpoint because the alternative — re-rendering the whole resource
    panel every few seconds to pick up new lines — throws away the reader's
    scroll position and their choice of tab along with it.
    """
    c = _gitops_conn(conn)
    if not c:
        return PlainTextResponse("", status_code=409)
    try:
        node = gitops.find_node(gitops.tree(c, name), uid)
        if not node or node.get("kind") != "Pod":
            return PlainTextResponse("", status_code=404)
        return PlainTextResponse(gitops.pod_log(
            c, name, node.get("name", ""), node.get("namespace", ""),
            container))
    except Exception as e:                                    # noqa: BLE001
        return PlainTextResponse(str(e)[:200], status_code=502)


@app.get("/gitops/app/op", response_class=HTMLResponse)
def gitops_operation(request: Request, conn: str, name: str):
    """The running sync, as a fragment the page replaces every couple of
    seconds. Its own endpoint so watching costs one small request, not a
    re-render of the resource tree underneath it."""
    c = _gitops_conn(conn)
    if not c:
        return HTMLResponse("", status_code=409)
    try:
        op = gitops.operation(c, name)
    except Exception as e:                                    # noqa: BLE001
        return templates.TemplateResponse(
            request, "gitops_op.html", ctx(request, op=None, op_error=str(e)[:200]))
    return templates.TemplateResponse(
        request, "gitops_op.html", ctx(request, op=op, op_error=""))


@app.get("/gitops/app/op.json")
def gitops_operation_json(request: Request, conn: str, name: str):
    """The running operation as data, for the DIAGRAM to paint itself with.

    Its own endpoint rather than the HTML fragment: the watcher marks boxes on
    the map now, and re-parsing a rendered table to find out which resource an
    operation touched would be reading our own output back."""
    c = _gitops_conn(conn)
    if not c:
        return JSONResponse({"phase": "", "running": False, "resources": []},
                            status_code=409)
    try:
        op = gitops.operation(c, name)
    except Exception as e:                                    # noqa: BLE001
        return JSONResponse({"phase": "", "running": False, "resources": [],
                             "error": str(e)[:200]})
    return JSONResponse({
        "phase": op.get("phase", ""), "running": bool(op.get("running")),
        "ok": bool(op.get("ok")), "failed": op.get("failed", 0),
        "message": op.get("message", ""),
        "resources": [{"kind": r.get("kind", ""), "name": r.get("name", ""),
                       "namespace": r.get("namespace", ""),
                       "status": r.get("status", ""),
                       "message": r.get("message", "")}
                      for r in (op.get("resources") or [])]})


@app.get("/gitops/app/graph.json")
def gitops_graph_json(request: Request, conn: str, name: str,
                      fresh: str = ""):
    """The resource map, re-rendered, for the page to swap in while a rollout
    happens.

    The layout stays on the server — reimplementing it in the browser would be
    two tidy-tree algorithms to keep in step — so this returns the same partial
    the page draws plus the new canvas size, and the page animates the
    difference: a box that has appeared fades in, one that has gone shows as
    terminating before it leaves. `fresh=1` skips the tree cache, because a
    caller watching a restart wants the churn, not a snapshot from before it.
    """
    c = _gitops_conn(conn)
    if not c:
        return JSONResponse({"error": "gone"}, status_code=409)
    try:
        if fresh:
            gitops.drop(c, name)
        tree = gitops.tree(c, name)
        # the live map carries the application root too, or the picture would
        # lose its own root every time it refreshed
        app = gitops.app_view(c, name)[0]
        g = gitops.graph(tree, app.get("name", name), app.get("health", ""),
                         app.get("sync", ""))
    except Exception as e:                                    # noqa: BLE001
        return JSONResponse({"error": str(e)[:200]}, status_code=502)
    inner = templates.get_template("_gitops_graph.html").render(
        {"graph": g, "glyph": logos.glyph})
    return JSONResponse({
        "inner": inner, "width": g["width"], "height": g["height"],
        "count": tree.get("count", 0),
        "by_health": tree.get("by_health", {}),
        "by_sync": tree.get("by_sync", {}),
    })


@app.get("/gitops/app/sync/panel", response_class=HTMLResponse)
def gitops_sync_panel(request: Request, conn: str, name: str):
    """The Synchronize panel as a fragment.

    So the applications list can open the real thing in a drawer instead of
    navigating to the application page just to reveal it — which is what "only
    the drawer, not everything" means. It renders the SAME partial the app page
    includes, so the options cannot differ by where somebody started.
    """
    c = _gitops_conn(conn)
    if not c:
        return HTMLResponse("", status_code=409)
    import html as _html
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_app = pool.submit(gitops.app_view, c, name)
        f_tree = pool.submit(gitops.tree, c, name)
        try:
            # app_view returns a TUPLE — (application, operation, history) — so
            # it is unpacked, not subscripted. Subscripting it raised a
            # TypeError that only showed up as a 500 in the drawer.
            app_row, _op, _hist = f_app.result()
            tree = f_tree.result()
        except gitops.GitOpsError as e:
            return HTMLResponse(
                f'<div class="sdrawer-b"><div class="flash err">'
                f'{_html.escape(str(e)[:300])}</div></div>')
    return templates.TemplateResponse(
        request, "_gitops_sync.html",
        {"request": request, "conn": {**c, "id": conn},
         "app": app_row, "tree": tree,
         "sync_flags": gitops.SYNC_FLAGS,
         "prune_policies": gitops.PRUNE_POLICIES})


@app.post("/gitops/app/policy")
async def gitops_app_policy(request: Request, conn: str, name: str):
    """Turn an application's automated sync on or off.

    Argo CD's own toggle, in the portal: an app with auto-sync off applies
    nothing until somebody syncs it, which is a real operational choice and the
    one setting people came to this page looking for.
    """
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    f = await request.form()
    to = f"/gitops/app?conn={conn}&name={urllib.parse.quote(name)}"
    automated = bool(f.get("automated"))
    me = getattr(request.state, "user", None)
    try:
        note = await run_in_threadpool(
            gitops.set_sync_policy, c, name, automated,
            bool(f.get("prune")), bool(f.get("self_heal")))
    except gitops.GitOpsError as e:
        auth.audit(me, "gitops_policy_failed", f"{c.get('name', conn)}:{name}",
                   str(e)[:200], _client_ip(request))
        return back(err=str(e)[:300], to=to)
    auth.audit(me, "gitops_policy", f"{c.get('name', conn)}:{name}", note,
               _client_ip(request))
    return back(msg=note, to=to)


@app.post("/gitops/repo/add")
async def gitops_repo_add(request: Request, conn: str):
    """Register a repository with Argo CD.

    The step that blocks a new application from syncing at all, and until now
    the only place to do it was Argo CD's own UI. Argo validates the credential
    as part of the call, so a wrong password is refused here rather than
    surfacing later as a mystery.
    """
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    f = await request.form()
    to = f"/gitops?conn={conn}#settings"
    me = getattr(request.state, "user", None)
    try:
        note = await run_in_threadpool(
            gitops.add_repo, c, str(f.get("url", "")),
            str(f.get("username", "")), str(f.get("password", "")),
            str(f.get("name", "")), str(f.get("project", "")),
            bool(f.get("insecure")))
    except gitops.GitOpsError as e:
        auth.audit(me, "gitops_repo_add_failed", str(f.get("url", ""))[:120],
                   str(e)[:200], _client_ip(request))
        return back(err=str(e)[:300], to=to)
    # the URL only — never the credential, which is Argo CD's to hold now
    auth.audit(me, "gitops_repo_added", str(f.get("url", ""))[:120],
               f"on {c.get('name', conn)}", _client_ip(request))
    return back(msg=note, to=to)


@app.post("/gitops/repo/remove")
async def gitops_repo_remove(request: Request, conn: str):
    """Drop a repository's credentials from Argo CD. Applications on it stop
    syncing, so the URL is typed back before it happens."""
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    f = await request.form()
    to = f"/gitops?conn={conn}#settings"
    url = str(f.get("url", "")).strip()
    if str(f.get("confirm", "")).strip() != url:
        return back(err="type the repository URL to confirm — applications on "
                        "it stop syncing", to=to)
    me = getattr(request.state, "user", None)
    try:
        note = await run_in_threadpool(gitops.remove_repo, c, url)
    except gitops.GitOpsError as e:
        return back(err=str(e)[:300], to=to)
    auth.audit(me, "gitops_repo_removed", url[:120],
               f"on {c.get('name', conn)}", _client_ip(request))
    return back(msg=note, to=to)


@app.post("/gitops/app/refresh")
async def gitops_refresh(request: Request, conn: str, name: str):
    """Ask the controller to re-read git. Nothing in the cluster changes, so
    this needs no confirmation — but it is still recorded, because "who made
    it notice" is a fair question afterwards."""
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    f = await request.form()
    hard = bool(f.get("hard"))
    to = f"/gitops/app?conn={conn}&name={urllib.parse.quote(name)}"
    try:
        detail = await run_in_threadpool(gitops.refresh_app, c, name, hard)
    except Exception as e:                                    # noqa: BLE001
        return back(err=str(e)[:300], to=to)
    auth.audit(request.state.user, "gitops_refresh",
               f"{c.get('name', conn)}:{name}",
               "hard" if hard else "normal", _client_ip(request))
    return back(msg=detail, to=to)


@app.post("/gitops/app/sync")
async def gitops_sync(request: Request, conn: str, name: str):
    """Apply git to the cluster. The one action here that changes production,
    so it is typed-word confirmed and audited before and after."""
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    f = await request.form()
    prune = bool(f.get("prune"))
    dry = bool(f.get("dry"))
    # a SELECTIVE sync: "res" carries kind/name/namespace/group per chosen
    # object, so a reader who wants one of eleven changes gets one of eleven
    picked = []
    for raw in f.getlist("res"):
        bits = str(raw).split("|")
        if len(bits) == 4 and bits[1]:
            picked.append({"group": bits[0], "kind": bits[1],
                           "name": bits[2], "namespace": bits[3]})
    to = f"/gitops/app?conn={conn}&name={urllib.parse.quote(name)}"
    if not dry and str(f.get("confirm", "")).strip().casefold() != "sync":
        return back(err="Type sync to apply git to the cluster.", to=to)
    # everything Argo CD's own Synchronize panel offers
    revision = str(f.get("revision", "")).strip()
    apply_only = bool(f.get("apply_only"))
    force = bool(f.get("force"))
    retry = bool(f.get("retry"))
    policy = str(f.get("prune_policy", "")).strip()
    flags = [k for k in f.getlist("flag") if k in gitops.SYNC_FLAGS]
    auth.audit(request.state.user,
               "gitops_sync_dryrun" if dry else "gitops_sync",
               f"{c.get('name', conn)}:{name}",
               f"prune={'yes' if prune else 'no'}"
               + (f" resources={len(picked)}" if picked else " (all)")
               + (f" revision={revision}" if revision else "")
               + (f" opts={'+'.join(flags)}" if flags else "")
               + (" apply-only" if apply_only else "")
               + (" force" if force else ""),
               _client_ip(request))
    try:
        detail = await run_in_threadpool(
            gitops.sync_app, c, name, prune, dry, picked or None,
            revision, apply_only, force, flags, policy, retry)
    except Exception as e:                                    # noqa: BLE001
        auth.audit(request.state.user, "gitops_sync_failed",
                   f"{c.get('name', conn)}:{name}", str(e)[:300],
                   _client_ip(request))
        return back(err=str(e)[:300], to=to)
    # Argo CD's sync is asynchronous — the call above only queues it. Land on
    # the page already watching, so the operation is followed here rather than
    # in the tool the portal just drove.
    return back(msg=detail, to=to + "&watch=1")


def _res_node(f) -> dict:
    """The resource a per-object form is talking about."""
    return {"kind": str(f.get("rkind", "")), "name": str(f.get("rname", "")),
            "namespace": str(f.get("rns", "")), "group": str(f.get("rgroup", "")),
            "version": str(f.get("rversion", "")) or "v1",
            "uid": str(f.get("ruid", ""))}


@app.post("/gitops/app/resource/action")
async def gitops_resource_action(request: Request, conn: str, name: str):
    """Run one of Argo CD's own resource actions — restart a Deployment,
    suspend a CronJob, promote a Rollout. Operational rather than destructive,
    so it is a plain confirmation on the page; audited either way."""
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    f = await request.form()
    node, act = _res_node(f), str(f.get("action", ""))
    to = f"/gitops/app?conn={conn}&name={urllib.parse.quote(name)}"
    auth.audit(request.state.user, "gitops_resource_action",
               f"{c.get('name', conn)}:{name}",
               f"{act} on {node['kind']}/{node['name']}", _client_ip(request))
    try:
        detail = await run_in_threadpool(gitops.run_action, c, name, node, act)
    except Exception as e:                                    # noqa: BLE001
        return back(err=str(e)[:300], to=to)
    return back(msg=detail, to=to)


@app.post("/gitops/app/resource/delete")
async def gitops_resource_delete(request: Request, conn: str, name: str):
    """Delete one object from the cluster.

    The sharpest thing on this page: the typed word is checked HERE, not only
    in the browser, and the form marks itself `data-del-skip` so the house
    dialog does not prompt a second time for the same gesture."""
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    f = await request.form()
    node = _res_node(f)
    to = f"/gitops/app?conn={conn}&name={urllib.parse.quote(name)}"
    if str(f.get("confirm", "")).strip().casefold() != "delete":
        return back(err="Type delete to remove that object from the cluster.",
                    to=to)
    auth.audit(request.state.user, "gitops_resource_delete",
               f"{c.get('name', conn)}:{name}",
               f"{node['kind']}/{node['name']}"
               + (" orphan" if f.get("orphan") else ""), _client_ip(request))
    try:
        detail = await run_in_threadpool(
            gitops.delete_resource, c, name, node,
            bool(f.get("force")), bool(f.get("orphan")))
    except Exception as e:                                    # noqa: BLE001
        auth.audit(request.state.user, "gitops_resource_delete_failed",
                   f"{c.get('name', conn)}:{name}", str(e)[:300],
                   _client_ip(request))
        return back(err=str(e)[:300], to=to)
    return back(msg=detail, to=to)


@app.post("/gitops/app/rollback")
async def gitops_rollback(request: Request, conn: str, name: str):
    """Deploy a revision this application has already run. Changes production,
    so: typed word, audited before and after."""
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    f = await request.form()
    hid = f.get("id", "")
    to = f"/gitops/app?conn={conn}&name={urllib.parse.quote(name)}"
    if str(f.get("confirm", "")).strip().casefold() != "rollback":
        return back(err="Type rollback to deploy that revision again.", to=to)
    auth.audit(request.state.user, "gitops_rollback",
               f"{c.get('name', conn)}:{name}", f"history={hid}",
               _client_ip(request))
    try:
        detail = await run_in_threadpool(gitops.rollback, c, name, hid,
                                         bool(f.get("prune")))
    except Exception as e:                                    # noqa: BLE001
        auth.audit(request.state.user, "gitops_rollback_failed",
                   f"{c.get('name', conn)}:{name}", str(e)[:300],
                   _client_ip(request))
        return back(err=str(e)[:300], to=to)
    return back(msg=detail, to=to + "&watch=1")


@app.post("/gitops/app/terminate")
async def gitops_terminate(request: Request, conn: str, name: str):
    """Stop the operation that is running. Operational — a plain confirmation
    on the page — and audited, because "who stopped it" is asked afterwards."""
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    to = f"/gitops/app?conn={conn}&name={urllib.parse.quote(name)}"
    auth.audit(request.state.user, "gitops_terminate",
               f"{c.get('name', conn)}:{name}", "", _client_ip(request))
    try:
        detail = await run_in_threadpool(gitops.terminate, c, name)
    except Exception as e:                                    # noqa: BLE001
        return back(err=str(e)[:300], to=to)
    return back(msg=detail, to=to)


@app.post("/gitops/app/delete")
async def gitops_app_delete(request: Request, conn: str, name: str):
    """Delete the application. Cascade — Argo's own default — takes everything
    it deployed with it, so the typed word is the application's OWN NAME rather
    than a generic word: a muscle-memory "delete" cannot destroy an estate."""
    c = _gitops_conn(conn)
    if not c:
        return back(err="that controller is gone", to="/gitops")
    f = await request.form()
    cascade = bool(f.get("cascade"))
    to = f"/gitops/app?conn={conn}&name={urllib.parse.quote(name)}"
    if str(f.get("confirm", "")).strip() != name:
        return back(err=f"Type {name} to delete the application.", to=to)
    auth.audit(request.state.user, "gitops_app_delete",
               f"{c.get('name', conn)}:{name}",
               "cascade" if cascade else "app only", _client_ip(request))
    try:
        detail = await run_in_threadpool(gitops.delete_app, c, name, cascade)
    except Exception as e:                                    # noqa: BLE001
        auth.audit(request.state.user, "gitops_app_delete_failed",
                   f"{c.get('name', conn)}:{name}", str(e)[:300],
                   _client_ip(request))
        return back(err=str(e)[:300], to=to)
    # the application is gone; there is no page left to land on
    return back(msg=detail, to=f"/gitops?platform=argocd&conn={conn}")


@app.get("/gitops/app/diff", response_class=HTMLResponse)
async def gitops_app_diff(request: Request, conn: str, name: str):
    """Everything a sync would change, in one page — the question Argo CD's own
    UI makes you answer one resource at a time. A fragment, so the app page
    opens it without navigating away from what is on screen."""
    c = _gitops_conn(conn)
    if not c:
        return HTMLResponse("", status_code=409)
    try:
        got = await run_in_threadpool(gitops.app_diff, c, name)
    except Exception as e:                                    # noqa: BLE001
        return HTMLResponse(
            f'<div class="flash err">⚠ {str(e)[:240]}</div>')
    return templates.TemplateResponse(
        request, "gitops_diff.html",
        ctx(request, d=got, conn=c, app_name=name))


@app.get("/workflows", response_class=HTMLResponse)
def workflows_page(request: Request, refresh: str = "", sec: str = ""):
    if refresh:
        workflows.invalidate()
    conns = store.all_wf()

    def one(c):
        try:
            return {"conn": c, "over": workflows.overview(c, refresh=bool(refresh)),
                    "provider": workflows.PROVIDERS.get(c.get("type")), "error": ""}
        except Exception as e:                                # noqa: BLE001
            return {"conn": c, "over": {"groups": [], "unit": "group",
                                        "running": 0, "failed": 0},
                    "provider": workflows.PROVIDERS.get(c.get("type")),
                    "error": str(e)[:200]}
    engines, pending = gather.across("workflows", conns, one,
                                     refresh=bool(refresh))
    return templates.TemplateResponse(
        request, "workflows.html",
        ctx(request, conns=conns, engines=engines, sec=sec, pending=pending,
            running=sum(e["over"].get("running", 0) for e in engines),
            failed=sum(e["over"].get("failed", 0) for e in engines)))


def _wf_conn(cid: str) -> dict | None:
    for c in store.all_wf():
        if c.get("id") == cid:
            return c
    return None


# Workflow IDs are arbitrary strings — the ones in this estate contain "${...}"
# and could contain a slash — so an execution is addressed by query string
# rather than by path segment. A slash in a path param silently becomes a
# different route and answers 404.
@app.get("/workflows/{cid}/{ns}", response_class=HTMLResponse)
def wf_browse(request: Request, cid: str, ns: str,
              type: str = "", wid: str = "", queue: str = "", since: str = "",
              raw: str = "", token: str = "", size: int = 50):
    """Executions in one namespace, filtered.

    Every filter is a query parameter and nothing is held server-side, so a
    filtered view is a URL that can be pasted into a ticket.
    """
    c = _wf_conn(cid)
    if not c or c.get("type") != "temporal":
        return RedirectResponse("/workflows", 303)
    # Read as a repeated parameter rather than one comma-joined string, so the
    # checkboxes are a plain form that works with JavaScript switched off.
    picked = [s for s in request.query_params.getlist("status") if s]
    view = str(request.query_params.get("view") or "")
    now = dt.datetime.now(dt.timezone.utc)
    saved = workflows.views(
        (now - dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    chosen = next((v for v in saved if v["key"] == view and v["key"]), None)
    # A saved view is a query, so it lands in the same box the operator could
    # have typed it into — visible, editable, and not a hidden mode.
    if chosen and not raw.strip():
        raw = chosen["query"]
    try:
        attrs = workflows.search_attributes(c, ns)
    except Exception as e:                                    # noqa: BLE001
        attrs = {"custom": [], "system": [], "why": str(e)[:200]}
    # Attribute filters arrive as parallel lists — one row of the Add Filter UI
    # is af[i]/ao[i]/av[i]. Zipped rather than indexed so a missing value in one
    # row cannot silently pair a name with the next row's operator.
    names = request.query_params.getlist("af")
    ops = request.query_params.getlist("ao")
    vals = request.query_params.getlist("av")
    kinds = {a["name"]: a["type"]
             for a in (attrs.get("custom", []) + attrs.get("system", []))}
    picked_attrs = []
    for i, name in enumerate(names):
        if not name.strip():
            continue
        picked_attrs.append({
            "name": name.strip(),
            "op": ops[i] if i < len(ops) else "=",
            "value": vals[i] if i < len(vals) else "",
            "type": kinds.get(name.strip(), "KEYWORD")})
    f = {"status": picked, "type": type.strip(), "wid": wid.strip(),
         "queue": queue.strip(), "since": since.strip(), "raw": raw.strip(),
         "attrs": picked_attrs}
    try:
        found = workflows.search(c, ns, f, token=token, size=size)
    except Exception as e:                                    # noqa: BLE001
        found = {"rows": [], "token": "", "query": "", "error": str(e)[:300]}
    try:
        spaces = workflows.namespaces(c)
    except Exception:                                         # noqa: BLE001
        spaces = [{"name": ns, "note": "", "retention": ""}]
    # The pills count what the rest of the filters already narrowed to, so they
    # describe the list on screen rather than the whole namespace. Counted
    # without the status clause, or every pill but one would read zero.
    base = workflows.build_query({**f, "status": []})
    try:
        tally = workflows.counts(c, ns, base)
    except Exception as e:                                    # noqa: BLE001
        tally = {"total": 0, "by_status": {}, "available": False, "why": str(e)}
    return templates.TemplateResponse(
        request, "wf_browse.html",
        ctx(request, conn=c, ns=ns, namespaces=spaces, found=found, filters=f,
            picked=picked, statuses=workflows.STATUSES, size=size,
            token=token, raw=raw, views=saved, view=view, tally=tally,
            attrs=attrs, picked_attrs=picked_attrs, ops=workflows.OPS))


@app.get("/workflows/{cid}/{ns}/run", response_class=HTMLResponse)
def wf_run(request: Request, cid: str, ns: str, id: str = "", run: str = "",
           order: str = ""):
    """One execution: what it is, what is pending, why it stopped, every event."""
    c = _wf_conn(cid)
    if not c or c.get("type") != "temporal":
        return RedirectResponse("/workflows", 303)
    detail, hist, err = None, None, ""
    lanes, window, polls = [], ("", ""), {"rows": [], "why": "", "rate": 0}
    try:
        detail = workflows.describe(c, ns, id, run)
        hist = workflows.history(c, ns, id, run,
                                 newest_first=(order == "new"))
        # The timeline is stitched from the events already fetched — it is not a
        # second request, and it is drawn oldest-first whichever way the table is
        # sorted, because a chart that flips direction is unreadable.
        rows = sorted(hist["events"], key=lambda e: workflows._int(e["id"]))
        lanes = workflows.timeline(rows)
        window = workflows.span(rows)
        polls = workflows.pollers(c, ns, detail["queue"])
    except Exception as e:                                    # noqa: BLE001
        err = str(e)[:300]
    return templates.TemplateResponse(
        request, "wf_run.html",
        ctx(request, conn=c, ns=ns, detail=detail, hist=hist, err=err,
            wid=id, rid=run, order=order, human=_human_bytes,
            lanes=lanes, window=window, polls=polls,
            tspan=workflows.epoch))


@app.get("/bmc", response_class=HTMLResponse)
def bmc_page(request: Request, device: str = "", refresh: str = ""):
    if refresh:
        bmc.invalidate()
    conns = store.all_bmc()
    try:
        asset_names = {a["id"]: a.get("hostname", a["id"])
                       for a in assets.search("", None, "hostname", limit=500)["rows"]}
    except Exception:                                         # noqa: BLE001
        asset_names = {}
    sel = next((c for c in conns if c["id"] == device), None) if device else None
    if sel:
        try:
            info, error = bmc.read(sel, refresh=bool(refresh)), ""
        except Exception as e:                                # noqa: BLE001
            info, error = {}, str(e)[:240]
        return templates.TemplateResponse(
            request, "bmc.html", ctx(request, conns=conns, sel=sel, info=info,
                            error=error, asset_names=asset_names, rows=[],
                            unhealthy=0, unreachable=0))

    def one(c):
        try:
            got = bmc.read(c, refresh=bool(refresh))
            return {"conn": c, "info": got, "error": "", "ok": got.get("ok", True)}
        except Exception as e:                                # noqa: BLE001
            return {"conn": c, "info": {}, "error": str(e)[:160], "ok": False}
    rows, pending = gather.across("bmc", conns, one, refresh=bool(refresh))
    # faults first: this page exists to surface the unhappy box
    rows.sort(key=lambda r: (r["ok"] and not r["error"],
                             r["conn"].get("name", "")))
    return templates.TemplateResponse(
        request, "bmc.html",
        ctx(request, conns=conns, sel=None, rows=rows, asset_names=asset_names,
            pending=pending,
            unhealthy=sum(1 for r in rows if not r["ok"] and not r["error"]),
            unreachable=sum(1 for r in rows if r["error"]),
            info={}, error=""))


@app.get("/virt", response_class=HTMLResponse)
def virt_page(request: Request, q: str = "", stopped_only: str = "",
              refresh: str = ""):
    if refresh:
        virt.invalidate()
    conns = store.all_virt()
    needle = q.strip().lower()

    def one(c):
        try:
            data = virt.read(c, refresh=bool(refresh))
            err = ""
        except Exception as e:                                # noqa: BLE001
            data, err = {"hosts": [], "guests": [], "running": 0, "stopped": 0}, \
                str(e)[:200]
        keep = []
        for g in data["guests"]:
            live = (g["state"] or "").lower() in ("running", "on", "poweredon")
            if stopped_only and live:
                continue
            if needle and needle not in " ".join(
                    [g["name"], g["host"], g["id"]]).lower():
                continue
            keep.append(g)
        return {"conn": c, "data": data, "guests": keep, "error": err,
                "provider": virt.PROVIDERS.get(c.get("type"))}
    engines, pending = gather.across("virt", conns, one, refresh=bool(refresh))
    return templates.TemplateResponse(
        request, "virt.html",
        ctx(request, conns=conns, engines=engines, q=q, pending=pending,
            stopped_only=bool(stopped_only),
            hosts=sum(len(e["data"]["hosts"]) for e in engines),
            guests=sum(len(e["data"]["guests"]) for e in engines),
            running=sum(e["data"].get("running", 0) for e in engines),
            stopped=sum(e["data"].get("stopped", 0) for e in engines)))


def _human_bytes(n) -> str:
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "—"


@app.get("/vpn", response_class=HTMLResponse)
def vpn_page(request: Request, refresh: str = "", msg: str = "", err: str = ""):
    if refresh:
        vpn.invalidate()
    portals = vpn.read_all(store.all_vpn())
    servers = [s for p in portals if p["data"] for s in p["data"]["servers"]]
    return templates.TemplateResponse(
        request, "vpn.html",
        ctx(request, portals=portals, providers=vpn.PROVIDERS,
            human=_human_bytes, msg=msg, err=err,
            totals={
                "connected": sum(p["data"]["connected"] for p in portals if p["data"]),
                "users": sum(p["data"]["users"] for p in portals if p["data"]),
                "servers": len(servers),
                "online": sum(1 for s in servers if s["online"]),
                "down": sum(1 for p in portals if p["error"]),
            }))


# ── the database console ───────────────────────────────────────
# The only place in the portal that holds a credential it was not given at
# deploy time. It holds it in memory, for one person, for one server, and the
# browser only ever carries a random ticket that names it. See dbconn.py.
def _db_ticket(request: Request, cid: str) -> str:
    return str((request.session.get("db_tickets") or {}).get(cid, ""))


def _db_engine(server: dict | str | None):
    """Which module drives this server: the SQL console, or Couchbase.

    Both expose the same lifecycle — connect, open_console, console, session,
    set_write, close_console — so every route below works on either by asking
    here first. A document store cannot be driven through dbconn.Console: there
    is no cursor and no transaction to open, and branching inside those methods
    would ruin them for the two engines that do have both.
    """
    if isinstance(server, str):
        server = _db_server(server) or {}
    kind = (server or {}).get("type", "")
    if dbconn.PROVIDERS.get(kind, {}).get("engine") == "couchbase":
        return cbase
    return dbconn


def _db_open(request: Request, cid: str) -> dict | None:
    """The credentials for this server in this session, or None."""
    me = getattr(request.state, "user", None)
    if not me:
        return None
    return _db_engine(cid).session(_db_ticket(request, cid), cid, me["id"])


def _db_console(request: Request, cid: str):
    """The live console — the object holding the open connections."""
    me = getattr(request.state, "user", None)
    if not me:
        return None
    return _db_engine(cid).console(_db_ticket(request, cid), cid, me["id"])


def _db_gone(request: Request, cid: str) -> str:
    """Why there is no console, in the words the operator needs.

    Being dropped back to a sign-in box with no explanation is the same
    experience whether the portal restarted, the session went an hour unused,
    or you signed out — and only one of those is worth being surprised by. The
    session carries the id of the process that issued its ticket, so a restart
    is knowable rather than guessed at.
    """
    if not _db_ticket(request, cid):
        return ""
    if request.session.get("db_boot") != dbconn.BOOT:
        return ("The portal restarted, so the credentials it was holding were "
                "dropped — they only ever live in memory. Sign in again to "
                "carry on.")
    return ("This console was closed — either signed out, or left unused for "
            "an hour. Sign in again to carry on.")


def _db_back(request: Request, cid: str) -> str:
    """Where to send them once they are back in. Only ever a path on this
    console: a redirect target from a query string is somewhere an attacker
    would like to choose."""
    want = str(request.query_params.get("back") or "").strip()
    if want.startswith(f"/db/{cid}") and "//" not in want and "\\" not in want:
        return want
    return f"/db/{cid}"


def _db_server(cid: str) -> dict | None:
    for c in store.all_db():
        if c.get("id") == cid:
            return c
    return None


@app.get("/db", response_class=HTMLResponse)
def db_page(request: Request, msg: str = "", err: str = "", open: str = "",
            back: str = ""):
    servers = store.all_db()
    for s in servers:
        s["_open"] = bool(_db_open(request, s.get("id", "")))
        s["_where"] = dbconn.label(s)
    return templates.TemplateResponse(
        request, "db.html",
        ctx(request, servers=servers, providers=dbconn.PROVIDERS,
            open_cid=open, why=_db_gone(request, open) if open else "",
            back=back if back.startswith(f"/db/{open}") else "",
            msg=msg, err=err))


@app.post("/db/{cid}/open")
async def db_open(request: Request, cid: str):
    server = _db_server(cid)
    if not server:
        return back(err="that server is not registered", to="/db")
    f = await request.form()
    user = str(f.get("user", "")).strip()
    password = str(f.get("password", ""))
    if not user:
        return back(err="a database username is needed", to=f"/db?open={cid}")
    me = request.state.user
    # Proved before the credentials are kept: holding a password that does not
    # work, and only finding out on the first query, is a worse experience and
    # leaves a useless secret in memory.
    eng = _db_engine(server)
    try:
        with contextlib.closing(eng.connect(
                server, {"user": user, "password": password})):
            pass
    except dbconn.DBError as e:
        auth.audit(me, "db_signin_failed", f"{server.get('name', cid)} as {user}",
                   str(e), _client_ip(request))
        return back(err=str(e), to=f"/db?open={cid}")
    ticket = eng.open_console(cid, me["id"], user, password, server)
    tickets = dict(request.session.get("db_tickets") or {})
    tickets[cid] = ticket
    request.session["db_tickets"] = tickets
    request.session["db_boot"] = dbconn.BOOT
    auth.audit(me, "db_console_opened", f"{server.get('name', cid)} "
               f"({dbconn.label(server)}) as {user}", "read-only",
               _client_ip(request))
    return RedirectResponse(_db_back(request, cid), 303)


@app.post("/db/{cid}/close")
async def db_close(request: Request, cid: str):
    _db_engine(cid).close_console(_db_ticket(request, cid))
    tickets = dict(request.session.get("db_tickets") or {})
    tickets.pop(cid, None)
    request.session["db_tickets"] = tickets
    auth.audit(request.state.user, "db_console_closed", cid, ip=_client_ip(request))
    return back(msg="console closed — the credentials are gone", to="/db")


@app.post("/db/{cid}/write")
async def db_write_mode(request: Request, cid: str):
    """Switching a console into write mode. Deliberately its own action with
    its own audit line: after this, statements can change data, and "when did
    this session gain the ability" should be answerable on its own."""
    held = _db_open(request, cid)
    server = _db_server(cid)
    if not held or not server:
        return back(err="that console is closed — open it again", to="/db")
    f = await request.form()
    on = str(f.get("on", "")) == "1"
    if on and str(f.get("confirm", "")).strip().casefold() != "write":
        return back(err="Type write to allow statements that change data.",
                    to=f"/db/{cid}")
    _db_engine(cid).set_write(_db_ticket(request, cid), on)
    auth.audit(request.state.user,
               "db_write_enabled" if on else "db_write_disabled",
               f"{server.get('name', cid)} ({dbconn.label(server)}) as "
               f"{held['user']}", ip=_client_ip(request))
    return back(msg="write mode is on — every statement is recorded" if on
                else "back to read-only", to=f"/db/{cid}")

TABS = ("overview", "tables", "query", "roles", "activity", "locks")

# Couchbase's own tabs. A different engine answers different questions, so it
# gets its own set rather than empty versions of "tables" and "locks".
CB_TABS = ("overview", "buckets", "xdcr", "indexes", "query", "users")


def _cb_ctx(con, server: dict, tab: str, result=None, sql: str = "",
            err: str = "") -> dict:
    """One Couchbase tab's data, and nothing else's.

    Each loader is wrapped on its own: a cluster where XDCR is refused to this
    account should still render its buckets. The refusal travels as
    `section_error` so the tab can print the reason where the table would be —
    an empty table with no explanation is the outcome worth avoiding.
    """
    out = {"server": server, "held": cbase.session_of(con),
           "where": cbase.label(server), "human": _human_bytes,
           "provider": dbconn.PROVIDERS.get(server.get("type"), {}),
           "tabs": CB_TABS, "result": result, "sql": sql,
           "max_rows": cbase.MAX_ROWS, "timeout": cbase.QUERY_TIMEOUT,
           "overview": None, "buckets": [], "xdcr": None, "indexes": None,
           "users": None, "history": con.history, "section_error": err,
           "version": {}, "rebalance": None, "roles": None, "detail": None}
    try:
        out["version"] = con.version()
    except dbconn.DBError as e:
        out["section_error"] = out["section_error"] or str(e)
    loaders = {"overview": con.overview, "buckets": con.buckets,
               "xdcr": con.xdcr, "indexes": con.indexes, "users": con.users}
    if tab in loaders:
        try:
            out[tab] = loaders[tab]()
        except dbconn.DBError as e:
            out["section_error"] = str(e)
    # Each of these is a second call, so it is fetched only for the tab that
    # shows it — and wrapped on its own, because a cluster that refuses the
    # role catalogue must still render the user list beside it.
    extra = {"overview": ("rebalance", con.rebalance),
             "users": ("roles", con.roles)}
    if tab in extra:
        key, load = extra[tab]
        try:
            out[key] = load()
        except dbconn.DBError as e:
            out["section_error"] = out["section_error"] or str(e)
    # The header counts buckets, so the overview tab is not the only one that
    # needs them — but a failure there must not blank the tab being viewed.
    if tab != "buckets":
        try:
            out["buckets"] = con.buckets()
        except dbconn.DBError:
            pass
    return out


@app.get("/db/{cid}", response_class=HTMLResponse)
def db_console(request: Request, cid: str, tab: str = "overview",
               database: str = "", msg: str = "", err: str = ""):
    """The console shell, with the opening tab rendered into it.

    Tabs after this one are fetched as fragments, so changing tab costs one
    small request instead of re-rendering the header, the counters and the
    database list every time. On a database in another region that was the
    difference between three seconds and one round trip.
    """
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not server:
        return RedirectResponse("/db?err=that+server+is+not+registered", 303)
    if not con:
        back = urllib.parse.quote(str(request.url.path) +
                                  ("?" + str(request.url.query)
                                   if request.url.query else ""), safe="")
        return RedirectResponse(f"/db?open={cid}&back={back}", 303)
    if _db_engine(server) is cbase:
        tab = tab if tab in CB_TABS else "overview"
        return templates.TemplateResponse(
            request, "cb_console.html",
            ctx(request, tab=tab, msg=msg, err=err,
                **_cb_ctx(con, server, tab)))
    tab = tab if tab in TABS else "overview"
    head, fragment = _shell_ctx(con, server, database)
    # the shell and the tab describe the same console, so they share keys —
    # merged rather than splatted twice, which is a TypeError
    merged = {**_tab_ctx(con, server, tab, fragment["database"]), **head}
    return templates.TemplateResponse(
        request, "db_console.html", ctx(request, tab=tab, msg=msg, err=err, **merged))


@app.get("/db/{cid}/tab/{tab}", response_class=HTMLResponse)
def db_tab(request: Request, cid: str, tab: str, database: str = "",
           refresh: str = ""):
    """One tab, as a fragment. Answers 409 when the console has been closed so
    the page can say so rather than swapping a login form into a panel."""
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server:
        return HTMLResponse("closed", status_code=409)
    if _db_engine(server) is cbase:
        if tab not in CB_TABS:
            raise HTTPException(404)
        if refresh:
            con.forget()
        return templates.TemplateResponse(
            request, f"cbtabs/{tab}.html",
            ctx(request, tab=tab, **_cb_ctx(con, server, tab)))
    if tab not in TABS:
        raise HTTPException(404)
    if refresh:
        con.forget()
    return templates.TemplateResponse(
        request, f"dbtabs/{tab}.html",
        ctx(request, tab=tab, **_tab_ctx(con, server, tab, database)))


@app.get("/db/{cid}/head", response_class=HTMLResponse)
def db_head(request: Request, cid: str, database: str = "", refresh: str = ""):
    """Just the counters. Its own fragment so Refresh does not reload a page."""
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server:
        return HTMLResponse("closed", status_code=409)
    if refresh:
        con.forget()
    if _db_engine(server) is cbase:
        return templates.TemplateResponse(
            request, "cbtabs/_head.html",
            ctx(request, **_cb_ctx(con, server, "overview")))
    head, _ = _shell_ctx(con, server, database, force=bool(refresh))
    return templates.TemplateResponse(request, "dbtabs/_head.html", ctx(request, **head))


def _shell_ctx(con, server: dict, database: str, force: bool = False):
    """The header: counters and the database list. One statement each, cached
    on the console, so a tab change does not pay for them again."""
    out = {"server": server, "held": dbconn.session_of(con),
           "provider": dbconn.PROVIDERS.get(server.get("type"), {}),
           "where": dbconn.label(server), "overview": None, "databases": [],
           "section_error": ""}
    try:
        out["overview"] = con.overview(database, force=force)
        out["databases"] = con.databases(force=force)
    except dbconn.DBError as e:
        out["section_error"] = str(e)
    current = database or (out["overview"] or {}).get("current", "")
    out["database"] = current
    return out, {"database": current}


def _tab_ctx(con, server: dict, tab: str, database: str, result=None,
             sql: str = "", err: str = "") -> dict:
    """Only what this tab needs. The first version loaded the overview and the
    database list for every tab, which is three round trips to show a table
    listing that needs one."""
    out = {"server": server, "held": dbconn.session_of(con), "database": database,
           "where": dbconn.label(server), "result": result, "sql": sql,
           "max_rows": dbconn.MAX_ROWS, "timeout": dbconn.QUERY_TIMEOUT,
           "page_size": dbconn.PAGE, "human": _human_bytes,
           "provider": dbconn.PROVIDERS.get(server.get("type"), {}),
           "tables": [], "roles": [], "activity": [], "locks": [],
           "history": con.history, "section_error": err}
    loaders = {"tables": lambda: con.tables(database),
               "roles": con.roles, "activity": con.activity,
               "locks": con.locks}
    if tab in loaders:
        try:
            out[tab] = loaders[tab]()
        except dbconn.DBError as e:
            out["section_error"] = str(e)
    if tab == "overview":
        try:
            out["databases"] = con.databases()
            out["tables"] = con.tables(database)
        except dbconn.DBError as e:
            out["section_error"] = str(e)
    return out


@app.get("/db/{cid}/export/targets.json")
def db_export_targets(request: Request, cid: str, database: str = ""):
    """The schemas and tables the dialog offers. Cached with the schema map."""
    con = _db_console(request, cid)
    if not con:
        return JSONResponse({"error": "that console is closed — open it again"},
                            status_code=409)
    try:
        return JSONResponse({"schemas": con.export_targets(database)})
    except dbconn.DBError as e:
        return JSONResponse({"error": str(e)}, status_code=502)


@app.get("/db/{cid}/export.sql")
def db_export_dump(request: Request, cid: str, database: str = "", schema: str = "",
              tables: str = "", data: str = "1", drop: str = ""):
    """Stream the dump out as a file.

    Streamed rather than built and then sent: a table of a few million rows
    would otherwise be assembled in memory first, and the browser would sit on
    a blank page until it was. This way the download starts immediately.
    """
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server:
        return RedirectResponse(f"/db?open={cid}", 303)
    picked = [t for t in (tables or "").split(",") if t.strip()]
    name = (database or server.get("database") or "database").strip()
    part = f"-{schema}" if schema else ""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"{server.get('name', 'db')}-{name}{part}-{stamp}.sql"
    filename = "".join(c if c.isalnum() or c in "._-" else "-" for c in filename)

    def body():
        try:
            yield from con.export(database, schema=schema, tables=picked,
                                  data=data == "1", drop=bool(drop))
        except dbconn.DBError as e:
            # the response has already begun, so the only honest place left to
            # report a failure is inside the file itself
            yield f"\n-- EXPORT FAILED: {e}\n"

    auth.audit(getattr(request.state, "user", None), "db_export",
               f"{server.get('name', cid)} · {name}{part}",
               "structure and data" if data == "1" else "structure only",
               _client_ip(request))
    return StreamingResponse(
        body(), media_type="application/sql",
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "Cache-Control": "no-store"})


class _Sink:
    """A file object for zipfile that only ever moves forward.

    zipfile writes a seekable archive when it can and falls back to data
    descriptors when it cannot. Deliberately offering no tell() or seek() puts
    it in the second mode, which is the one that can be streamed: the
    alternative is building the whole archive in memory before the browser
    sees a byte, and one of these databases is 290 MB.
    """

    def __init__(self):
        self.buf = bytearray()

    def write(self, chunk) -> int:
        self.buf += chunk
        return len(chunk)

    def flush(self) -> None:
        pass

    def drain(self) -> bytes:
        out = bytes(self.buf)
        del self.buf[:]
        return out


@app.get("/db/{cid}/export-all.zip")
def db_export_all(request: Request, cid: str, data: str = "1", drop: str = ""):
    """Every database on the server, one .sql per database, in a zip."""
    import zipfile
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server:
        return RedirectResponse(f"/db?open={cid}", 303)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    filename = "".join(c if c.isalnum() or c in "._-" else "-"
                       for c in f"{server.get('name', 'db')}-all-{stamp}.zip")

    def body():
        sink = _Sink()
        try:
            with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED,
                                 compresslevel=6) as zf:
                for name, chunks in con.export_all(data=data == "1",
                                                   drop=bool(drop)):
                    with zf.open(name, "w") as f:
                        for chunk in chunks:
                            f.write(chunk.encode("utf-8"))
                            if len(sink.buf) > 96_000:
                                yield sink.drain()
                    yield sink.drain()
        except dbconn.DBError as e:
            # the archive is already part-written, so the only place left to
            # say anything is a file inside it
            with zipfile.ZipFile(sink, "a", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("EXPORT-FAILED.txt", f"{e}\n")
        yield sink.drain()

    auth.audit(getattr(request.state, "user", None), "db_export_all",
               server.get("name", cid),
               "structure and data" if data == "1" else "structure only",
               _client_ip(request))
    return StreamingResponse(
        body(), media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "Cache-Control": "no-store"})


@app.get("/db/{cid}/schema.json")
def db_schema(request: Request, cid: str, database: str = ""):
    """Tables and columns for the editor's completion. Fetched once per
    database and held by the browser, so typing costs nothing."""
    con = _db_console(request, cid)
    if not con:
        return JSONResponse({"error": "closed"}, status_code=409)
    try:
        return JSONResponse(con.schema_map(database))
    except dbconn.DBError as e:
        return JSONResponse({"error": str(e), "tables": [],
                             "keywords": dbconn.KEYWORDS})


@app.get("/db/{cid}/table", response_class=HTMLResponse)
def db_table(request: Request, cid: str, database: str = "", schema: str = "",
             name: str = "", page: int = 1, order: str = "", desc: str = ""):
    """One table: its columns, keys, indexes and a page of its rows."""
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server:
        return HTMLResponse("closed", status_code=409)
    out = _tab_ctx(con, server, "table", database)
    try:
        out["detail"] = con.table(database, schema, name)
        out["data"] = con.rows(database, schema, name, page, order, bool(desc))
    except dbconn.DBError as e:
        out["detail"], out["data"] = None, None
        out["section_error"] = str(e)
    return templates.TemplateResponse(request, "dbtabs/table.html",
                                      ctx(request, tab="tables", **out))


@app.post("/db/{cid}/cbquery", response_class=HTMLResponse)
async def cb_query(request: Request, cid: str):
    """One SQL++ statement against the query service.

    Its own route rather than a branch inside db_query: that one carries
    `database` and `explain`, neither of which means anything here, and the
    audit line is a different sentence.
    """
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server or _db_engine(server) is not cbase:
        return HTMLResponse("closed", status_code=409)
    f = await request.form()
    sql = str(f.get("sql", ""))
    result, err = None, ""
    started = time.time()
    try:
        result = con.query(sql)
    except dbconn.DBError as e:
        err = str(e)
    outcome = err or (result and result.get("error")) or (
        f"{len(result['rows'])} row(s)" if result else "no result")
    auth.audit(request.state.user, "cb_write" if con.write else "cb_query",
               f"{server.get('name', cid)} ({cbase.label(server)}) as {con.user}",
               (sql.strip()[:900] + (" …" if len(sql.strip()) > 900 else ""))
               + f"  → {outcome}, {int((time.time() - started) * 1000)}ms",
               _client_ip(request))
    return templates.TemplateResponse(
        request, "cbtabs/query.html",
        ctx(request, tab="query",
            **_cb_ctx(con, server, "query", result=result, sql=sql, err=err)))


@app.get("/db/{cid}/cbbucket", response_class=HTMLResponse)
def cb_bucket_detail(request: Request, cid: str, name: str = ""):
    """One bucket, as a fragment: its settings and its scopes and collections."""
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server or _db_engine(server) is not cbase:
        return HTMLResponse("closed", status_code=409)
    out = _cb_ctx(con, server, "buckets")
    try:
        out["detail"] = con.bucket_detail(name)
    except dbconn.DBError as e:
        out["section_error"] = str(e)
    return templates.TemplateResponse(request, "cbtabs/bucket.html",
                                      ctx(request, tab="buckets", **out))


@app.post("/db/{cid}/rebalance")
async def cb_rebalance(request: Request, cid: str):
    """Start or stop a rebalance.

    Audited either way and either way it is a cluster-wide operation, so the
    line records which it was and who asked. cbase refuses unless the console is
    in write mode, and refuses outright if the cluster did not name all of its
    nodes — see rebalance_start.
    """
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server or _db_engine(server) is not cbase:
        return back(err="that console is closed — open it again", to="/db")
    f = await request.form()
    stop = str(f.get("stop", "")) == "1"
    to = f"/db/{cid}?tab=overview"
    if not stop and str(f.get("confirm", "")).strip().casefold() != "rebalance":
        return back(err="Type rebalance to confirm — this moves data across "
                        "every node in the cluster.", to=to)
    try:
        msg = con.rebalance_stop() if stop else con.rebalance_start()
    except dbconn.DBError as e:
        auth.audit(request.state.user, "cb_rebalance_refused",
                   f"{server.get('name', cid)} ({cbase.label(server)}) as "
                   f"{con.user}", str(e), _client_ip(request))
        return back(err=str(e), to=to)
    auth.audit(request.state.user,
               "cb_rebalance_stopped" if stop else "cb_rebalance_started",
               f"{server.get('name', cid)} ({cbase.label(server)}) as "
               f"{con.user}", msg, _client_ip(request))
    return back(msg=msg, to=to)


@app.post("/db/{cid}/cbuser")
async def cb_user_save(request: Request, cid: str):
    """Create or change a local Couchbase account.

    The audit line names the account and the roles and never the password —
    cbase.user_save returns a message built not to contain it.
    """
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server or _db_engine(server) is not cbase:
        return back(err="that console is closed — open it again", to="/db")
    f = await request.form()
    uid = str(f.get("uid", "")).strip()
    to = f"/db/{cid}?tab=users"
    try:
        msg = con.user_save(uid, str(f.get("name", "")),
                            str(f.get("roles", "")),
                            password=str(f.get("password", "")),
                            new=bool(f.get("new")))
    except dbconn.DBError as e:
        auth.audit(request.state.user, "cb_user_refused",
                   f"{server.get('name', cid)} ({cbase.label(server)}) as "
                   f"{con.user}", f"{uid}: {e}", _client_ip(request))
        return back(err=str(e), to=to)
    auth.audit(request.state.user, "cb_user_saved",
               f"{server.get('name', cid)} ({cbase.label(server)}) as "
               f"{con.user}", msg, _client_ip(request))
    return back(msg=msg, to=to)


@app.post("/db/{cid}/bucket")
async def cb_bucket_new(request: Request, cid: str):
    """Create a bucket. Write mode is enforced in cbase, not here, so the rule
    holds for any future caller and not just this form."""
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server or _db_engine(server) is not cbase:
        return back(err="that console is closed — open it again", to="/db")
    f = await request.form()
    name = str(f.get("bucket", "")).strip()
    to = f"/db/{cid}?tab=buckets"
    try:
        msg = con.bucket_create(
            name,
            str(f.get("ram", "")).strip(),
            replicas=str(f.get("replicas", "1")).strip() or "1",
            btype=str(f.get("btype", "membase")).strip() or "membase",
            eviction=str(f.get("eviction", "")).strip(),
            flush=bool(f.get("flush")))
    except dbconn.DBError as e:
        auth.audit(request.state.user, "cb_bucket_refused",
                   f"{server.get('name', cid)} ({cbase.label(server)}) as "
                   f"{con.user}", f"{name}: {e}", _client_ip(request))
        return back(err=str(e), to=to)
    auth.audit(request.state.user, "cb_bucket_created",
               f"{server.get('name', cid)} ({cbase.label(server)}) as "
               f"{con.user}", msg, _client_ip(request))
    return back(msg=msg, to=to)


@app.post("/db/{cid}/query", response_class=HTMLResponse)
async def db_query(request: Request, cid: str):
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server:
        return HTMLResponse("closed", status_code=409)
    f = await request.form()
    sql = str(f.get("sql", ""))
    database = str(f.get("database", "")).strip()
    explain = bool(f.get("explain"))
    result, err = None, ""
    started = time.time()
    try:
        result = con.run(sql, database, explain=explain)
    except dbconn.DBError as e:
        err = str(e)
        con.remember(sql, database, None, err)
    # Every statement, whether it worked or not, with who ran it and where.
    # A refused write is as worth recording as a successful one.
    auth.audit(request.state.user,
               "db_explain" if explain
               else ("db_write" if con.write else "db_query"),
               f"{server.get('name', cid)} ({dbconn.label(server)})"
               f"{' · ' + database if database else ''} as {con.user}",
               (sql.strip()[:900] + (" …" if len(sql.strip()) > 900 else ""))
               + (f"  → {err}" if err else
                  f"  → {result['affected'] if result and result['affected'] >= 0 else len(result['rows'])} "
                  f"row(s), {int((time.time() - started) * 1000)}ms"),
               _client_ip(request))
    return templates.TemplateResponse(
        request, "dbtabs/query.html",
        ctx(request, tab="query",
            **_tab_ctx(con, server, "query", database, result=result, sql=sql,
                       err=err), explained=explain))


@app.post("/db/{cid}/export")
async def db_export(request: Request, cid: str):
    """The result of a statement as CSV.

    The statement is run again rather than the last result being kept: holding
    a full result set in memory per session to make a download work is a way to
    run the portal out of memory, and re-running a SELECT is cheap.
    """
    con = _db_console(request, cid)
    server = _db_server(cid)
    if not con or not server:
        return RedirectResponse(f"/db?open={cid}", 303)
    f = await request.form()
    sql = str(f.get("sql", ""))
    database = str(f.get("database", "")).strip()
    try:
        out = con.run(sql, database, limit=100_000)
    except dbconn.DBError as e:
        return back(err=str(e), to=f"/db/{cid}?tab=query&database={database}")
    auth.audit(request.state.user, "db_export",
               f"{server.get('name', cid)} ({dbconn.label(server)}) as {con.user}",
               f"{len(out['rows'])} row(s): {sql.strip()[:400]}",
               _client_ip(request))
    buf = io.StringIO()
    w = csvsafe.writer(buf)
    w.writerow(out["columns"])
    w.writerows(out["rows"])
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return Response(
        buf.getvalue(), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="query-{stamp}.csv"'})


# ── the four integration kinds that share one settings template ──
# Each entry is everything the generic page and the generic CRUD need. Adding
# an integration is a module with PROVIDERS/test(), plus one row here — no new
# template and no new routes.
CONN_SPECS = {
    "edge": {
        "module": edge, "title": "Edge & DNS", "noun": "provider",
        "page": "/edge", "page_label": "Edge & DNS", "area": "edge",
        "store": "edge",
        "blurb": "Connect Cloudflare, Fastly, Bunny or NS1 — the layer every "
                 "request passes through before it reaches anything else in this "
                 "portal. Zones, DNS records, TLS position, certificates, cache "
                 "state, tunnels and Workers, in the place you already have the "
                 "clusters and the pipelines.",
        "readonly": "Reading is read-only. The few changes offered — purging a "
                    "cache, development mode, a DNS record, blocking an address — "
                    "are the ones made under pressure, and each is confirmed and "
                    "recorded. Plans, domain transfers and deleting a zone stay "
                    "in the provider's console.",
    },
    "gitops": {
        "module": gitops, "title": "GitOps controllers", "noun": "controller",
        "page": "/gitops", "page_label": "GitOps", "area": "gitops",
        "store": "gitops",
        "blurb": "Connect Argo CD, or point Flux at a cluster the portal "
                 "already knows. Add as many as you run — one per environment, "
                 "or one per cluster. Each controller gets its own page of "
                 "applications, and every application its resource tree.",
        "readonly": "Reading is everything Argo CD's own UI shows. Refresh "
                    "asks the controller to re-read git and changes nothing. "
                    "Sync does change the cluster: it is behind a dialog that "
                    "names the destination, pruning is off unless ticked, a "
                    "dry run is offered first, and every sync is written to "
                    "the audit log. Rollback and delete stay in Argo CD. Flux "
                    "is read-only here — it has no API to call.",
    },
    "wf": {
        "module": workflows, "title": "Workflow engines", "noun": "engine",
        "page": "/workflows", "page_label": "Workflows", "area": "workflows",
        "store": "wf",
        "blurb": "Connect Temporal or Airflow to see what is running and what "
                 "failed recently, next to the clusters those workers run on.",
        "readonly": "Read-only: cancelling or terminating a workflow is a "
                    "business decision with consequences the portal cannot see, "
                    "so it stays in the engine's own UI.",
    },
    "bmc": {
        "module": bmc, "title": "Server hardware (BMC)", "noun": "BMC",
        "page": "/bmc", "page_label": "Server hardware", "area": "bmc",
        "store": "bmc",
        "blurb": "Register the out-of-band controllers — iDRAC, iLO, XCC, "
                 "Supermicro — by their Redfish endpoint. One protocol covers "
                 "every vendor, and the vendor and model are read from the BMC "
                 "rather than typed here.",
        "readonly": "Read-only, deliberately: Redfish can power-cycle a server, "
                    "and a web page that can do that by mis-click is not worth "
                    "the convenience. Every row links to the BMC's own UI.",
    },
    "vpn": {
        "module": vpn, "title": "VPN portals", "noun": "portal",
        "page": "/vpn", "page_label": "VPN", "area": "vpn",
        "store": "vpn",
        "blurb": "Connect Pritunl, OpenVPN Access Server, wg-easy or Netmaker. "
                 "Nearly everything else in this portal — a BMC, a hypervisor, "
                 "a database, a cluster API — is reachable only from inside the "
                 "network, and this is how people get inside it. Add as many as "
                 "you run: several sites, or one per environment.",
        "readonly": "Read-only: no enabling or disabling a user, no restarting "
                    "a server, no revoking a certificate. Those are account "
                    "decisions, and each tool already has a console with the "
                    "permissions and the audit trail for them.",
    },
    "db": {
        "module": dbconn, "title": "Database servers", "noun": "server",
        "page": "/db", "page_label": "Databases", "area": "db",
        "store": "db",
        # Both engines negotiate TLS themselves and neither takes a CA here,
        # so a "skip TLS verification" box would be a control over nothing.
        "tls_option": False,
        "blurb": "Register PostgreSQL and MySQL/MariaDB servers by host and "
                 "port. Add as many as you run — one row per server, across "
                 "every environment. No username and no password is stored "
                 "here: whoever opens the console types their own, they are "
                 "held for that session only, and they are gone when the "
                 "portal restarts.",
        "readonly": "The console opens read-only, and the server itself "
                    "enforces it — a read-only transaction, not a check on the "
                    "text you typed. Write mode is a deliberate switch, and "
                    "every statement run after it is written to the audit log "
                    "with who ran it and against which server.",
    },
    "virt": {
        "module": virt, "title": "Hypervisors", "noun": "hypervisor",
        "page": "/virt", "page_label": "Hypervisors", "area": "virt",
        "store": "virt",
        "blurb": "Connect Proxmox VE, vCenter or a standalone ESXi host to see "
                 "the hosts and virtual machines underneath your clusters.",
        "readonly": "Read-only: no start, stop, migrate or snapshot. Those "
                    "belong in the hypervisor's own console with its own "
                    "permissions and audit trail.",
    },
}


def _conn_ctx(kind: str) -> dict:
    spec = CONN_SPECS[kind]
    mod = spec["module"]
    projects = store.projects()
    cluster_names = {}
    for pid, p in projects.items():
        for cid, c in (p.get("clusters") or {}).items():
            cluster_names[cid] = f"{p.get('name', pid)} · {c.get('name', cid)}"
    try:
        asset_names = {a["id"]: a.get("hostname", a["id"])
                       for a in assets.search("", None, "hostname", limit=500)["rows"]}
    except Exception:                                         # noqa: BLE001
        asset_names = {}
    # Every field any provider of this kind declares, in declaration order. The
    # add form renders one row per key and hides the ones the chosen type does
    # not ask for, so a provider gaining a field needs no template change.
    all_fields: list[str] = []
    for pv in mod.PROVIDERS.values():
        for key in pv.get("fields", {}):
            if key not in all_fields:
                all_fields.append(key)
    return {
        "kind": kind, "title": spec["title"], "noun": spec["noun"],
        "all_fields": all_fields, "tls_option": spec.get("tls_option", True),
        "blurb": spec["blurb"], "readonly_note": spec["readonly"],
        "page": spec["page"], "page_label": spec["page_label"],
        "conns": getattr(store, f"all_{spec['store']}")(),
        "providers": mod.PROVIDERS,
        "provider_fields": {k: v.get("fields", {})
                            for k, v in mod.PROVIDERS.items()},
        "provider_notes": {k: v.get("note", "") for k, v in mod.PROVIDERS.items()},
        "provider_hints": {k: v.get("url_hint", "")
                           for k, v in mod.PROVIDERS.items()},
        "project_names": {pid: p.get("name", pid) for pid, p in projects.items()},
        "cluster_names": cluster_names, "asset_names": asset_names,
    }


def _conn_form(kind: str, f) -> dict:
    """Only the fields this provider declares, so a form cannot smuggle in
    values the integration never asked for."""
    spec = CONN_SPECS[kind]
    kindname = str(f.get("type", "")).strip()
    prov = spec["module"].PROVIDERS.get(kindname, {})
    out = {"type": kindname, "name": str(f.get("name", "")).strip(),
           "skip_tls": "1" if f.get("skip_tls") else ""}
    for key in prov.get("fields", {}):
        val = str(f.get(key, "")).strip()
        if key == "base_url":
            val = val.rstrip("/")
        out[key] = val
    return out


@app.get("/settings/conns/{kind}", response_class=HTMLResponse)
def settings_conns(request: Request, kind: str, msg: str = "", err: str = ""):
    if kind not in CONN_SPECS:
        return RedirectResponse("/settings", 303)
    return templates.TemplateResponse(
        request, "set_conns.html", ctx(request, msg=msg, err=err, **_conn_ctx(kind)))


@app.post("/settings/conns/{kind}/new")
async def conn_new(request: Request, kind: str):
    if kind not in CONN_SPECS:
        return RedirectResponse("/settings", 303)
    spec = CONN_SPECS[kind]
    f = await request.form()
    conn = _conn_form(kind, f)
    conn["token"] = str(f.get("token", ""))
    back_to = f"/settings/conns/{kind}"
    if conn["type"] not in spec["module"].PROVIDERS:
        return back(err=f"choose a {spec['noun']} type", to=back_to)
    prov = spec["module"].PROVIDERS[conn["type"]]
    if not conn["name"]:
        conn["name"] = prov["label"]
    missing = [prov["fields"].get(k, k) for k in prov["needs"]
               if not conn.get(k)]
    if missing:
        return back(err=f"missing for {prov['label']}: {', '.join(missing)}",
                    to=back_to)
    ok, detail = await run_in_threadpool(spec["module"].test, conn)
    conn["status"] = ("ok: " if ok else "failed: ") + detail
    getattr(store, f"add_{spec['store']}")(str(f.get("pid", "")), conn)
    auth.audit(getattr(request.state, "user", None), f"{kind}_connected",
               f"{conn['type']}:{conn['name']}", detail, _client_ip(request))
    return (back(msg=f"{conn['name']} — {detail}", to=back_to) if ok
            else back(err=f"added, but the check failed: {detail}", to=back_to))


@app.post("/settings/conns/{kind}/{cid}/update")
async def conn_update(request: Request, kind: str, cid: str):
    if kind not in CONN_SPECS:
        return RedirectResponse("/settings", 303)
    spec = CONN_SPECS[kind]
    f = await request.form()
    pid = str(f.get("pid", ""))
    existing = getattr(store, f"get_{spec['store']}")(pid, cid) or {}
    fields = _conn_form(kind, {**dict(f), "type": existing.get("type", "")})
    fields.pop("type", None)
    if str(f.get("token", "")):
        fields["token"] = str(f.get("token"))
    getattr(store, f"update_{spec['store']}")(pid, cid, **fields)
    spec["module"].invalidate()
    ok, detail = await run_in_threadpool(
        spec["module"].test, getattr(store, f"get_{spec['store']}")(pid, cid) or {})
    getattr(store, f"update_{spec['store']}")(
        pid, cid, status=("ok: " if ok else "failed: ") + detail)
    to = f"/settings/conns/{kind}"
    return back(msg=detail, to=to) if ok else back(err=detail, to=to)


@app.post("/settings/conns/{kind}/{cid}/test")
async def conn_test(request: Request, kind: str, cid: str):
    if kind not in CONN_SPECS:
        return RedirectResponse("/settings", 303)
    spec = CONN_SPECS[kind]
    f = await request.form()
    pid = str(f.get("pid", ""))
    ok, detail = await run_in_threadpool(
        spec["module"].test, getattr(store, f"get_{spec['store']}")(pid, cid) or {})
    getattr(store, f"update_{spec['store']}")(
        pid, cid, status=("ok: " if ok else "failed: ") + detail)
    to = f"/settings/conns/{kind}"
    return back(msg=detail, to=to) if ok else back(err=detail, to=to)


@app.post("/settings/conns/{kind}/{cid}/delete")
async def conn_delete(request: Request, kind: str, cid: str):
    if kind not in CONN_SPECS:
        return RedirectResponse("/settings", 303)
    spec = CONN_SPECS[kind]
    f = await request.form()
    pid = str(f.get("pid", ""))
    conn = getattr(store, f"get_{spec['store']}")(pid, cid) or {}
    getattr(store, f"delete_{spec['store']}")(pid, cid)
    if kind == "db":
        # Anyone with a console open against this server loses it now. Leaving
        # live credentials in memory for a server the portal no longer knows
        # about would be a way in that no page any longer shows.
        dbconn.forget_server(cid)
    auth.audit(getattr(request.state, "user", None), f"{kind}_removed",
               conn.get("name", cid), ip=_client_ip(request))
    return back(msg=f"{spec['noun']} removed", to=f"/settings/conns/{kind}")


# ── Clouds ─────────────────────────────────────────────────────
def _subnet_use(inv: dict) -> list:
    """[(name, percent used, free)] for the subnet tile.

    The capacity comes from the subnet's own CIDR. The tile divided by 253 —
    right for a /24 and wrong for everything else, so a /20 with 4,091 addresses
    free came out as more than 100% used and the bar ran off the end.
    """
    import ipaddress
    rows = []
    for g in inv.get("groups") or []:
        if g.get("key") != "subnets":
            continue
        for r in g.get("rows") or []:
            free = str(r.get("extra", "")).split(" ")[0]
            pct = 0.0
            try:
                net = ipaddress.ip_network(str(r.get("kind", "")).strip(),
                                           strict=False)
                # both clouds keep a handful of addresses per subnet for
                # themselves, so usable is a little under the total
                usable = max(1, net.num_addresses - 5)
                pct = max(0.0, min(100.0,
                                   (usable - int(free)) / usable * 100))
            except (ValueError, TypeError):
                pct = 0.0
            rows.append((r.get("name", ""), round(pct, 1), free,
                         r.get("kind", "")))
    return rows[:6]


def _cloud_search(sel: dict, inv: dict | None = None) -> list:
    """Everything on this account that can be jumped to, for the search box.

    Built here and handed to the page whole: the inventory is already in memory
    and an account this size is a few kilobytes of index, so searching is
    instant and needs no round trip. A server-side search would be a request per
    keystroke to find something the page already knows.
    """
    # A page that does not read the inventory — bills, a console — still gets a
    # search box: without one, following a result would mean losing the thing
    # that found it. The services come from the product table, which needs no
    # network at all; the resources are only there when an inventory is.
    if inv is None:
        inv = cloud.peek(sel) or {}
    region = inv.get("region", "") or sel.get("region", "")
    out = [{"t": "page", "label": "Bills", "sub": "spend by month and product",
            "icon": "💳", "url": f"/clouds/bills?account={sel['id']}",
            "words": cloud.SERVICE_WORDS.get("billing", "")}]
    table = (cloud.AWS_PRODUCTS if sel.get("type") == "aws"
             else cloud.ALI_PRODUCTS)
    if not inv.get("groups") and sel.get("type") in ("alibaba", "aws"):
        for key, label, icon, *_rest in table:
            out.append({"t": "service", "label": label, "sub": "not read yet",
                        "icon": icon,
                        "url": f"/clouds/r/{sel['id']}/{key}?region={region}",
                        "words": cloud.SERVICE_WORDS.get(key, "")})
        return out
    provider = sel.get("type", "")
    for g in inv.get("groups") or []:
        key = g.get("key", "")
        rows = g.get("rows") or []
        if key == "billing":
            continue
        base = f"/clouds/r/{sel['id']}/{key}?region={region}"
        out.append({"t": "service", "label": g.get("label", key),
                    "sub": f"{len(rows)} in {region}", "icon": g.get("icon", "•"),
                    "url": base, "words": cloud.SERVICE_WORDS.get(key, "")})
        if not cloudops.has_detail(key, provider):
            continue
        for r in rows[:400]:
            ident = (r.get("name") if key in cloud.NAME_KEYED
                     else r.get("id"))
            if not ident:
                continue
            out.append({
                "t": g.get("label", key), "label": r.get("name") or ident,
                "sub": " · ".join(x for x in (r.get("id"), r.get("kind"),
                                              r.get("extra")) if x)[:80],
                "icon": g.get("icon", "•"),
                "url": f"/clouds/r/{sel['id']}/{key}/{ident}?region={region}",
                "words": ""})
    return out


def _storage_summary(inv: dict) -> dict:
    """Disk and object storage totals, added up here rather than in the page.

    The size is inside the row's description ("cloud_essd · 40 GiB") because
    that is what reads well in a table; parsing it in a template would be
    unreadable, and a template cannot sum anything.
    """
    out = {"disks": 0, "disk_gib": 0, "buckets": 0, "snapshots": 0,
           "unattached": 0, "images": 0}
    for g in inv.get("groups") or []:
        rows = g.get("rows") or []
        if g.get("key") == "disks":
            out["disks"] = len(rows)
            for r in rows:
                got = re.search(r"(\d+)\s*GiB", str(r.get("kind", "")))
                if got:
                    out["disk_gib"] += int(got.group(1))
                if "not attached" in str(r.get("extra", "")):
                    out["unattached"] += 1
        elif g.get("key") in cloud.BUCKET_KEYS:
            out["buckets"] = len(rows)
        elif g.get("key") == "snapshots":
            out["snapshots"] = len(rows)
        elif g.get("key") == "images":
            out["images"] = len(rows)
    return out


def _cloud_account(request: Request, account: str):
    """(connection, error response) — one place for the checks every cloud page
    repeats: does it exist, and may this person see it."""
    me = getattr(request.state, "user", None)
    sel = next((c for c in store.all_cloud() if c["id"] == account), None)
    if not sel:
        raise HTTPException(404)
    if not rbac.may_project(me, sel.get("pid") or "", "clouds"):
        raise HTTPException(403)
    return sel


@app.get("/edge", response_class=HTMLResponse)
async def edge_page(request: Request, conn: str = "", group: str = "",
                    q: str = "", refresh: str = "", msg: str = "", err: str = ""):
    """Every edge and DNS provider, then one of them in depth.

    Same three levels the other integration pages use: what is connected, then a
    provider, then a group of rows inside it.
    """
    conns = store.all_edge()
    names = {pid: p["name"] for pid, p in store.projects().items()}
    if refresh:
        edge.invalidate()
    sel = next((c for c in conns if c["id"] == conn), None) if conn else None
    if sel and not rbac.may_project(getattr(request.state, "user", None),
                                    sel.get("pid") or "", "edge"):
        raise HTTPException(403)
    inv = await run_in_threadpool(edge.inventory, sel, bool(refresh)) if sel \
        else {}
    shown = None
    if sel and inv.get("groups"):
        shown = next((g for g in inv["groups"] if g["key"] == group),
                     inv["groups"][0])
    rows = list(shown["rows"]) if shown else []
    if q and rows:
        needle = q.lower()
        rows = [r for r in rows
                if any(needle in str(v).lower() for v in r.values())]
    # DNS is the group people manage rather than read, so it is grouped by zone
    # here: fifty-seven records in one flat list is a list, not a tool
    by_zone = []
    if shown and shown["key"] == "dns":
        order, buckets = [], {}
        for r in rows:
            z = r.get("zone", "")
            if z not in buckets:
                buckets[z] = []
                order.append(z)
            buckets[z].append(r)
        for z in order:
            zid = next((x["id"] for x in inv.get("zones") or []
                        if x["name"] == z), "")
            by_zone.append({"zone": z, "zone_id": zid,
                            "rows": sorted(buckets[z],
                                           key=lambda r: (r.get("kind", ""),
                                                          r.get("name", "")))})
    return templates.TemplateResponse(
        request, "edge.html",
        ctx(request, conns=conns, sel=sel, inv=inv, shown=shown, rows=rows, q=q,
            by_zone=by_zone,
            providers=edge.PROVIDERS, scope=names, msg=msg, err=err,
            # The DNS group has the per-row manager, which offers add, edit and
            # delete on the records themselves — so the generic accordion would be
            # a second, clumsier copy of the same three forms.
            actions=(edge.for_group(shown["key"], sel.get("type", ""))
                     if sel and shown and shown["key"] != "dns" else []),
            prefill={}))


@app.post("/edge/action")
async def edge_action(request: Request):
    """One change at the edge: a purge, a DNS record, a blocked address.

    The same three steps as a cloud action — confirm, audit, then act — because
    the blast radius is the same shape: a DNS record can take a site off the
    internet as surely as stopping an instance can.
    """
    f = await request.form()
    me = getattr(request.state, "user", None)
    conn = str(f.get("conn", ""))
    sel = next((c for c in store.all_edge() if c["id"] == conn), None)
    if not sel:
        raise HTTPException(404)
    if not rbac.may_project(me, sel.get("pid") or "", "edge"):
        raise HTTPException(403)
    key = str(f.get("action", ""))
    spec = edge.ACTIONS.get(key)
    back = f"/edge?conn={conn}&group={urllib.parse.quote(str(f.get('group', '')))}"
    if not spec:
        return RedirectResponse(f"{back}&err="
                                + urllib.parse.quote("unknown action"), 303)
    params = {p["name"]: str(f.get(p["name"], "")).strip() for p in spec["params"]}
    want = edge.confirm_word(key, params)
    typed = str(f.get("confirm", "")).strip()
    # a fixed word is matched however it was capitalised; that forgiveness would
    # be wrong for an id, which has to be exact
    if typed.casefold() != want.casefold():
        return RedirectResponse(
            f"{back}&err=" + urllib.parse.quote(
                f"type {want} to confirm — nothing was changed"), 303)
    line = edge.preview(key, params)
    auth.audit(me, "edge_action", f"{sel.get('name', '')} · {sel.get('type', '')}",
               line[:400], _client_ip(request))
    try:
        got = await run_in_threadpool(edge.run, sel, key, params)
    except Exception as e:                                    # noqa: BLE001
        auth.audit(me, "edge_action_failed",
                   f"{sel.get('name', '')} · {sel.get('type', '')}",
                   f"{line[:300]} → {e}", _client_ip(request))
        return RedirectResponse(f"{back}&err="
                                + urllib.parse.quote(str(e)[:300]), 303)
    return RedirectResponse(f"{back}&msg="
                            + urllib.parse.quote(got["message"][:300]), 303)


@app.get("/edge/export/{conn}/{group}.csv")
async def edge_export(request: Request, conn: str, group: str):
    sel = next((c for c in store.all_edge() if c["id"] == conn), None)
    if not sel:
        raise HTTPException(404)
    if not rbac.may_project(getattr(request.state, "user", None),
                            sel.get("pid") or "", "edge"):
        raise HTTPException(403)
    inv = await run_in_threadpool(edge.inventory, sel, False)
    g = next((x for x in inv.get("groups") or [] if x["key"] == group), None)
    if not g:
        raise HTTPException(404)
    buf = io.StringIO()
    w = csvsafe.writer(buf)
    cols = g.get("columns") or ["name", "type", "state", "detail", "zone"]
    w.writerow(["id"] + list(cols))
    for r in g["rows"]:
        w.writerow([r.get("id", ""), r.get("name", ""), r.get("kind", ""),
                    r.get("state", ""), r.get("extra", ""), r.get("zone", "")])
    name = re.sub(r"[^A-Za-z0-9._-]+", "-",
                  f"{sel.get('name', 'edge')}-{group}-{time.strftime('%Y-%m-%d')}.csv")
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ── TLS certificates ───────────────────────────────────────────
@app.get("/certs", response_class=HTMLResponse)
async def certs_page(request: Request, id: str = "", new: str = "",
                     sec: str = "", msg: str = "", err: str = ""):
    """Three views of one thing: what has been issued, a request form, and one
    order in progress.

    The order view is the important one, and it is deliberately a plain read of a
    database row: whoever opens it may be doing so ten seconds or ten hours after
    the records were pasted, and both have to render the same way.
    """
    every = await run_in_threadpool(certs.orders)
    order = next((o for o in every if o["id"] == id), None) if id else None
    terms = ""
    if new:
        # The subscriber agreement is the CA's, not ours, so it is fetched and
        # linked rather than described. A CA that cannot be reached still lets
        # the form render — the failure belongs on submit, where it can say so.
        # Fetched only for the form (?new=1); an empty estate now lands on the
        # overview with a create CTA, not straight in the form.
        terms = await run_in_threadpool(certs.terms, certs.CAS["le"][1])
    return templates.TemplateResponse(
        request, "certs.html",
        ctx(request, orders=every, order=order, show_new=bool(new), sec=sec,
            cas=certs.CAS, key_types=certs.KEY_TYPES,
            subject_fields=certs.SUBJECT_FIELDS, p12_modes=certs.P12_MODES,
            key_sources=certs.KEY_SOURCES, reusable=certs.reusable(every),
            terms=terms, msg=msg, err=err))


def _cert_or_404(oid: str) -> dict:
    got = certs.one(oid)
    if not got:
        raise HTTPException(404)
    return got


@app.post("/certs/new")
async def certs_new(request: Request):
    f = await request.form()
    me = getattr(request.state, "user", None)

    # A PROVIDER IS NOT AN ACME CA, so it does not go through `create`: there
    # is no directory, no account, no challenge and nothing to poll. All that
    # happens is a key and a CSR are made and held until a person brings the
    # signed certificate back.
    if str(f.get("ca", "")) == certs.EXTERNAL:
        try:
            oid = await run_in_threadpool(
                certs.create_external,
                (me or {}).get("id", ""),
                domains=str(f.get("domains", "")),
                name=str(f.get("name", "")),
                key_type=str(f.get("key_type", "rsa2048")),
                subject={k: str(f.get(f"subj_{k}", ""))
                         for k, *_ in certs.SUBJECT_FIELDS},
                note=str(f.get("note", "")))
        except certs.CertError as e:
            auth.audit(me, "cert_request_failed",
                       str(f.get("domains", ""))[:200], str(e)[:300],
                       _client_ip(request))
            return RedirectResponse("/certs?new=1&err="
                                    + urllib.parse.quote(str(e)[:400]), 303)
        got = certs.one(oid)
        auth.audit(me, "cert_csr_generated", ", ".join(got["domains"])[:200],
                   "CSR generated and held for a provider to sign",
                   _client_ip(request))
        return RedirectResponse(f"/certs?id={oid}", 303)

    try:
        # By keyword, every one of them. Twelve positional arguments through a
        # threadpool is a signature reorder away from requesting a certificate
        # with the passphrase in the CSR field, and nothing would say so.
        oid = await run_in_threadpool(
            certs.create,
            (me or {}).get("id", ""),
            domains=str(f.get("domains", "")),
            ca=str(f.get("ca", "le")),
            ca_url=str(f.get("ca_url", "")),
            email=str(f.get("email", "")),
            key_source=str(f.get("key_source", "new")),
            key_type=str(f.get("key_type", "rsa2048")),
            reuse_from=str(f.get("reuse_from", "")),
            key_pem_in=str(f.get("key_pem", "")),
            passphrase=str(f.get("passphrase", "")),
            csr_in=str(f.get("csr", "")),
            agreed=bool(f.get("agreed")))
    except certs.CertError as e:
        auth.audit(me, "cert_request_failed", str(f.get("domains", ""))[:200],
                   str(e)[:300], _client_ip(request))
        return RedirectResponse("/certs?new=1&err="
                                + urllib.parse.quote(str(e)[:400]), 303)
    got = certs.one(oid)
    auth.audit(me, "cert_requested", ", ".join(got["domains"])[:200],
               f"{got['ca_label']} · {got['key_desc']}", _client_ip(request))
    return RedirectResponse(f"/certs?id={oid}", 303)


@app.post("/certs/{oid}/check-anyway")
async def certs_check_anyway(request: Request, oid: str):
    """Ask the CA although this installation cannot see the records itself.

    Separate from /proceed because it is a different decision with a different
    cost: proceed only starts the waiting, this one spends the order.
    """
    got = _cert_or_404(oid)
    await run_in_threadpool(certs.check_anyway, oid)
    certs.kick(oid)
    auth.audit(getattr(request.state, "user", None), "cert_validate_blind",
               ", ".join(got["domains"])[:200],
               "asked the CA without local DNS confirmation",
               _client_ip(request))
    return RedirectResponse(f"/certs?id={oid}", 303)


@app.post("/certs/{oid}/proceed")
async def certs_proceed(request: Request, oid: str):
    """The records are in the DNS. From here on nobody has to be watching."""
    got = _cert_or_404(oid)
    await run_in_threadpool(certs.proceed, oid)
    # A head start, so somebody who is still on the page sees movement rather
    # than waiting out the worker's tick. The worker owns it either way.
    certs.kick(oid)
    auth.audit(getattr(request.state, "user", None), "cert_validate",
               ", ".join(got["domains"])[:200], "records reported in place",
               _client_ip(request))
    return RedirectResponse(f"/certs?id={oid}", 303)


@app.post("/certs/{oid}/check")
async def certs_check(request: Request, oid: str):
    """Look now, rather than at the next tick."""
    _cert_or_404(oid)
    await run_in_threadpool(certs.advance, oid)
    return RedirectResponse(f"/certs?id={oid}", 303)


@app.post("/certs/{oid}/cancel")
async def certs_cancel(request: Request, oid: str):
    got = _cert_or_404(oid)
    await run_in_threadpool(certs.cancel, oid)
    auth.audit(getattr(request.state, "user", None), "cert_cancelled",
               ", ".join(got["domains"])[:200], "", _client_ip(request))
    return RedirectResponse(f"/certs?id={oid}", 303)


@app.post("/certs/{oid}/delete")
async def certs_delete(request: Request, oid: str):
    got = _cert_or_404(oid)
    # Deleting an issued certificate deletes the private key with it, and there
    # is no second copy — so it is audited with what it was, not just its id.
    await run_in_threadpool(certs.remove, oid)
    auth.audit(getattr(request.state, "user", None), "cert_deleted",
               ", ".join(got["domains"])[:200],
               f"{got['status']} · key held: {got['has_key']}",
               _client_ip(request))
    return RedirectResponse("/certs?msg="
                            + urllib.parse.quote("the order was deleted"), 303)


@app.post("/certs/{oid}/renew")
async def certs_renew(request: Request, oid: str):
    f = await request.form()
    me = getattr(request.state, "user", None)
    same = str(f.get("same_key", "")) == "1"
    try:
        new_id = await run_in_threadpool(certs.renew, oid,
                                         (me or {}).get("id", ""), same)
    except certs.CertError as e:
        return RedirectResponse(f"/certs?id={oid}&err="
                                + urllib.parse.quote(str(e)[:400]), 303)
    auth.audit(me, "cert_renew", oid,
               "keeping the same private key" if same else "with a new key",
               _client_ip(request))
    return RedirectResponse(f"/certs?id={new_id}", 303)


@app.post("/certs/{oid}/attach")
async def certs_attach(request: Request, oid: str):
    """The signed certificate comes back from the provider and lands here.

    The checks are the feature -- anyone can save a file. The one that matters
    is that the certificate and the key held here are actually a pair: a
    mismatch produces a bundle that builds, deploys and then fails the
    handshake, which is discovered by somebody reading TLS logs at 02:00.
    """
    _cert_or_404(oid)
    f = await request.form()
    me = getattr(request.state, "user", None)
    pem = str(f.get("cert_pem", "") or "")
    up = f.get("cert_file")
    if hasattr(up, "read"):
        raw = await up.read()
        if raw:
            pem = raw.decode("utf-8", "replace")
    try:
        got = await run_in_threadpool(certs.attach_cert, oid, pem)
    except certs.CertError as e:
        auth.audit(me, "cert_attach_failed", oid, str(e)[:300],
                   _client_ip(request))
        return RedirectResponse(f"/certs?id={oid}&err="
                                + urllib.parse.quote(str(e)[:400]), 303)
    said = []
    if got.get("missing"):
        said.append("the provider did not include "
                    + ", ".join(got["missing"]))
    if got.get("extra"):
        said.append("it added " + ", ".join(got["extra"]))
    auth.audit(me, "cert_attached", oid,
               ("matched the stored key" if got.get("matched_key")
                else "stored without a key to match against")
               + ("; " + "; ".join(said) if said else ""),
               _client_ip(request))
    msg = "certificate stored" + (" and matched to the key held here"
                                  if got.get("matched_key") else "")
    return RedirectResponse(f"/certs?id={oid}&msg="
                            + urllib.parse.quote(msg), 303)


@app.post("/certs/{oid}/p12")
async def certs_p12(request: Request, oid: str):
    """The key, the certificate and the chain in one PKCS#12.

    A POST, not a GET, because the passphrase is in the body: a secret in a
    query string is a secret in every proxy log between here and the browser.
    """
    _cert_or_404(oid)
    f = await request.form()
    me = getattr(request.state, "user", None)
    try:
        name, blob = await run_in_threadpool(
            certs.pkcs12_bundle, oid, str(f.get("passphrase", "") or ""),
            str(f.get("mode", "modern")))
    except certs.CertError as e:
        return RedirectResponse(f"/certs?id={oid}&err="
                                + urllib.parse.quote(str(e)[:400]), 303)
    # Audited by name like the private key download, because it CONTAINS the
    # private key -- a p12 leaving the portal is the key leaving the portal.
    auth.audit(me, "cert_p12_download", name,
               "a PKCS#12 bundle (which contains the private key) was "
               "downloaded" + ("" if f.get("passphrase") else " WITH NO "
                               "PASSPHRASE"),
               _client_ip(request))
    return Response(content=blob, media_type="application/x-pkcs12",
                    headers={"Content-Disposition":
                             f'attachment; filename="{name}"'})


@app.get("/certs/{oid}/download/{kind}")
async def certs_download(request: Request, oid: str, kind: str):
    """One file. The private key is audited by name because it is the one thing
    here that leaving the portal actually matters — everything else in the set is
    public once the certificate is served."""
    _cert_or_404(oid)
    got = await run_in_threadpool(certs.files, oid)
    if kind not in got:
        raise HTTPException(404)
    name, body = got[kind]
    if kind == "privkey":
        auth.audit(getattr(request.state, "user", None), "cert_key_download",
                   name, "the private key was downloaded", _client_ip(request))
    return Response(content=body, media_type="application/x-pem-file",
                    headers={"Content-Disposition":
                             f'attachment; filename="{name}"'})


@app.get("/clouds/export/{account}/{what}.csv")
async def cloud_export(request: Request, account: str, what: str,
                       region: str = "", months: int = 12):
    """Any resource list, or the bills, as CSV.

    Everything on screen is exportable, because the answer to "can I get this in
    a spreadsheet" should never be "no". Built from the same rows the page
    renders, so an export cannot disagree with what was shown.
    """
    sel = _cloud_account(request, account)
    buf = io.StringIO()
    w = csvsafe.writer(buf)
    stamp = time.strftime("%Y-%m-%d")

    if what == "bills":
        bills = await run_in_threadpool(cloud.bills, sel,
                                        max(1, min(int(months or 12), 24)))
        w.writerow(["month", "product", "product code", "subscription",
                    "currency", "amount"])
        for m in bills["months"]:
            for r in m["rows"]:
                w.writerow([m["cycle"], r["product"], r["code"], r["kind"],
                            r["currency"] or bills["currency"], r["amount"]])
        w.writerow([])
        w.writerow(["month", "total"])
        for m in bills["months"]:
            w.writerow([m["cycle"], m["total"]])
        name = f"{sel.get('name', 'cloud')}-bills-{stamp}.csv"
    else:
        inv = await run_in_threadpool(cloud.inventory, sel, False, region)
        g = next((x for x in inv["groups"] if x["key"] == what), None)
        if not g:
            raise HTTPException(404)
        cols = g.get("columns") or ["name", "type", "state", "detail", "zone"]
        w.writerow(["id"] + list(cols))
        for r in g["rows"]:
            w.writerow([r.get("id", ""), r.get("name", ""), r.get("kind", ""),
                        r.get("state", ""), r.get("extra", ""), r.get("zone", "")])
        name = f"{sel.get('name', 'cloud')}-{what}-{inv.get('region', '')}-{stamp}.csv"

    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name)
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{safe}"'})


@app.get("/clouds/console/{account}/{instance}", response_class=HTMLResponse)
async def cloud_console(request: Request, account: str, instance: str,
                        region: str = "", err: str = "", msg: str = ""):
    """A link into Alibaba's own VNC console for one instance."""
    sel = _cloud_account(request, account)
    rid = region or (cloud.inventory(sel)).get("region", "")
    vnc_url = ""
    try:
        vnc_url = await run_in_threadpool(cloudops.vnc_link, sel, instance, rid)
    except cloudops.OpError as e:
        err = err or str(e)
    auth.audit(getattr(request.state, "user", None), "cloud_console",
               f"{sel.get('name', '')} · {instance}",
               "console link issued" if vnc_url else f"refused: {err}"[:200],
               _client_ip(request))
    return templates.TemplateResponse(
        request, "cloud_console.html",
        ctx(request, sel=sel, instance=instance, region=rid, vnc_url=vnc_url,
            search_index=_cloud_search(sel),
            actions=[a for a in cloudops.for_group("compute", sel.get("type", ""))
                     if a["key"] == "ecs.vnc_password"],
            prefill={"InstanceId": instance}, err=err, msg=msg,
            provider=cloud.PROVIDERS.get(sel.get("type"))))


@app.get("/clouds/bills", response_class=HTMLResponse)
async def cloud_bills(request: Request, account: str, months: int = 12,
                      month: str = ""):
    """Every month's bill, by product, with the trend.

    A separate page because it is a different question from "what do I have":
    "what did RDS cost in May" needs history, and history is one call per month.
    """
    sel = _cloud_account(request, account)
    bills = await run_in_threadpool(cloud.bills, sel,
                                    max(1, min(int(months or 12), 24)))
    # the month shown in full: whichever was asked for, else the newest
    cycles = [m["cycle"] for m in bills["months"]]
    shown = month if month in cycles else (cycles[-1] if cycles else "")
    pay = await run_in_threadpool(cloud.payments, sel)
    return templates.TemplateResponse(
        request, "cloud_bills.html",
        ctx(request, sel=sel, bills=bills, months=months, shown=shown, pay=pay,
            search_index=_cloud_search(sel),
            one=next((m for m in bills["months"] if m["cycle"] == shown), None),
            provider=cloud.PROVIDERS.get(sel.get("type"))))


@app.get("/clouds/r/{account}/{group}", response_class=HTMLResponse)
async def cloud_group(request: Request, account: str, group: str,
                      region: str = "", q: str = "", msg: str = "", err: str = ""):
    """One resource type in full, with the actions that apply to it."""
    sel = _cloud_account(request, account)
    inv = await run_in_threadpool(cloud.inventory, sel, False, region)
    g = next((x for x in inv["groups"] if x["key"] == group), None)
    if not g:
        raise HTTPException(404)
    rows = g["rows"]
    if q:
        needle = q.lower()
        rows = [r for r in rows
                if any(needle in str(v).lower() for v in r.values())]
    return templates.TemplateResponse(
        request, "cloud_group.html",
        ctx(request, sel=sel, inv=inv, group=g, rows=rows, q=q,
            search_index=_cloud_search(sel, inv),
            actions=cloudops.for_group(group, sel.get("type", "")),
            has_detail=cloudops.has_detail(group, sel.get("type", "")),
            name_keyed=cloud.NAME_KEYED,
            provider=cloud.PROVIDERS.get(sel.get("type")), msg=msg, err=err))


@app.get("/clouds/r/{account}/{group}/{ident:path}", response_class=HTMLResponse)
async def cloud_detail(request: Request, account: str, group: str, ident: str,
                       region: str = "", msg: str = "", err: str = ""):
    """One resource, as deep as the provider will describe it."""
    sel = _cloud_account(request, account)
    inv = await run_in_threadpool(cloud.inventory, sel, False, region)
    rid = inv.get("region") or region
    det = await run_in_threadpool(cloudops.detail, sel, group, ident, rid)
    g = next((x for x in inv["groups"] if x["key"] == group), None)
    return templates.TemplateResponse(
        request, "cloud_detail.html",
        ctx(request, sel=sel, inv=inv, group=g, group_key=group, ident=ident,
            search_index=_cloud_search(sel, inv),
            det=det, actions=cloudops.for_group(group, sel.get("type", "")),
            region=rid,
            # the id is already known, so the form does not ask for it again —
            # retyping an id is how the wrong one ends up in a delete
            prefill=cloudops.prefill_for(group, ident, sel.get("type", "")),
            can_shell=(group == "compute"),
            provider=cloud.PROVIDERS.get(sel.get("type")), msg=msg, err=err))


@app.post("/clouds/action")
async def cloud_action(request: Request):
    """Make one change to a cloud account.

    Three things happen before the call: the confirmation is checked, the exact
    call is written to the audit log, and only then is it made. The audit entry
    goes in first on purpose — an attempt that fails is as interesting as one
    that works, and a crash afterwards must not erase the fact that it was tried.
    """
    f = await request.form()
    account = str(f.get("account", ""))
    sel = _cloud_account(request, account)
    key = str(f.get("action", ""))
    spec = cloudops._provider_actions(sel.get("type", "")).get(key)
    region = str(f.get("region", "")) or (cloud.inventory(sel)).get("region", "")
    back_to = str(f.get("back", "")) or f"/clouds?account={account}"
    if not back_to.startswith("/"):
        back_to = f"/clouds?account={account}"
    if not spec:
        return RedirectResponse(
            f"{back_to}?err=" + urllib.parse.quote("unknown action"), 303)

    params = {p["name"]: str(f.get(p["name"], "")).strip()
              for p in spec["params"]}
    want = cloudops.confirm_word(key, params, sel.get("type", ""))
    if str(f.get("confirm", "")).strip() != want:
        return RedirectResponse(
            f"{back_to}?err=" + urllib.parse.quote(
                f"type {want} to confirm — nothing was changed"), 303)

    me = getattr(request.state, "user", None)
    line = cloudops.preview(key, params, sel.get("type", ""))
    auth.audit(me, "cloud_action", f"{sel.get('name', '')} · {region}",
               line[:400], _client_ip(request))
    try:
        got = await run_in_threadpool(cloudops.run, sel, key, params, region)
    except cloudops.OpError as e:
        auth.audit(me, "cloud_action_failed", f"{sel.get('name', '')} · {region}",
                   f"{line[:300]} → {e}", _client_ip(request))
        return RedirectResponse(f"{back_to}?err=" + urllib.parse.quote(str(e)[:300]),
                                303)
    except Exception as e:                                    # noqa: BLE001
        auth.audit(me, "cloud_action_failed", f"{sel.get('name', '')} · {region}",
                   f"{line[:300]} → {type(e).__name__}", _client_ip(request))
        return RedirectResponse(
            f"{back_to}?err=" + urllib.parse.quote(f"{type(e).__name__}: {e}"[:300]),
            303)
    cloud.invalidate()          # the inventory on screen is now out of date
    note = got["message"]
    data = got.get("data") or {}
    if data.get("AccessKeySecret"):
        # shown once, never stored: it goes in the redirect and nowhere else
        note += (f" · id {data['AccessKeyId']} · secret "
                 f"{data['AccessKeySecret']}")
    return RedirectResponse(f"{back_to}?msg=" + urllib.parse.quote(note[:500]), 303)


@app.get("/clouds/shell/{account}/{instance}", response_class=HTMLResponse)
async def cloud_shell(request: Request, account: str, instance: str,
                      region: str = "", invoke: str = "", err: str = ""):
    """Run a command on an instance, through Cloud Assistant.

    Not an interactive terminal: the API has no session, so a command is
    submitted and its output collected. For an audited portal that is the better
    shape anyway — every command run here is on the record with who ran it.
    """
    sel = _cloud_account(request, account)
    rid = region or (cloud.inventory(sel)).get("region", "")
    result = None
    if invoke:
        try:
            result = await run_in_threadpool(cloudops.command_result, sel,
                                             invoke, rid, instance)
        except cloudops.OpError as e:
            err = err or str(e)
    return templates.TemplateResponse(
        request, "cloud_shell.html",
        ctx(request, sel=sel, instance=instance, region=rid, invoke=invoke,
            search_index=_cloud_search(sel),
            result=result, err=err,
            provider=cloud.PROVIDERS.get(sel.get("type"))))


@app.post("/clouds/shell/{account}/{instance}")
async def cloud_shell_run(request: Request, account: str, instance: str):
    sel = _cloud_account(request, account)
    f = await request.form()
    script = str(f.get("script", ""))
    region = str(f.get("region", ""))
    me = getattr(request.state, "user", None)
    base = f"/clouds/shell/{account}/{instance}?region={urllib.parse.quote(region)}"
    if str(f.get("confirm", "")).strip() != "RUN":
        return RedirectResponse(f"{base}&err=type RUN to confirm", 303)
    auth.audit(me, "cloud_command", f"{sel.get('name', '')} · {instance}",
               script[:400], _client_ip(request))
    try:
        got = await run_in_threadpool(cloudops.run_command, sel, instance,
                                      script, region)
        done = await run_in_threadpool(cloudops.wait_for, sel, got["invoke_id"],
                                       region, 20, instance)
    except cloudops.OpError as e:
        auth.audit(me, "cloud_command_failed", f"{sel.get('name','')} · {instance}",
                   f"{script[:200]} → {e}", _client_ip(request))
        return RedirectResponse(f"{base}&err=" + urllib.parse.quote(str(e)[:300]), 303)
    auth.audit(me, "cloud_command_result", f"{sel.get('name','')} · {instance}",
               f"{done.get('status')} exit={done.get('exit')}", _client_ip(request))
    return RedirectResponse(f"{base}&invoke={urllib.parse.quote(got['invoke_id'])}",
                            303)


@app.get("/clouds", response_class=HTMLResponse)
def clouds_page(request: Request, account: str = "", refresh: str = "",
                region: str = ""):
    """Two levels: a card per account, then one account in depth with its live
    inventory and a map drawn from that inventory."""
    cloud.warm_start()          # idempotent
    if refresh:
        cloud.warm_now()        # collects behind the page, never blocks the click
    conns = store.all_cloud()
    names = {p_id: p["name"] for p_id, p in store.projects().items()}
    sel = next((c for c in conns if c["id"] == account), None) if account else None

    if sel:
        # one account, explicitly opened: fetching live here is the point
        # cloud resources are per region, so the page can be pointed at another
        # one without needing a second connection for the same account
        inv = cloud.inventory(sel, refresh=bool(refresh), region=region)
        prov = cloud.PROVIDERS.get(sel.get("type"))
        # spend for the strip at the top: whatever is cached, never a wait
        bills = (cloud.bills_peek(sel, 12)
                 if sel.get("type") in ("alibaba", "aws") else None)
        return templates.TemplateResponse(
            request, "clouds.html",
            ctx(request, conns=conns, sel=sel, inv=inv, provider=prov,
                bills=bills, topology=charts.cloud_topology(inv),
                # ranked in Python: sorting dicts by a list attribute in the
                # template compares the lists themselves, which raises
                storage=_storage_summary(inv),
                subnet_use=_subnet_use(inv),
                search_index=_cloud_search(sel, inv),
                mix=sorted(((g["label"], len(g["rows"]))
                            for g in (inv.get("groups") or [])
                            if g.get("key") != "billing" and g.get("rows")),
                           key=lambda x: -x[1])[:5],
                scope=names.get(sel.get("pid") or "", "All projects"),
                diagram=charts.cloud_map(
                    sel.get("name", ""),
                    (prov or {}).get("label", sel.get("type", "")),
                    inv.get("region", ""), inv.get("groups") or []),
                cards=[], providers_used=[], grand_total=0))

    # cache only: the warmer fetches, so this cannot be slow however many
    # accounts are configured or how far away their regions are
    cards = [{"conn": c, "provider": cloud.PROVIDERS.get(c.get("type")),
              "inv": cloud.peek(c) or {"groups": [], "notes": [], "total": 0,
                                       "error": "", "collecting": True}}
             for c in conns]
    return templates.TemplateResponse(
        request, "clouds.html",
        ctx(request, conns=conns, sel=None, cards=cards,
            providers_used=sorted({c["conn"].get("type") for c in cards}),
            grand_total=sum(c["inv"].get("total", 0) for c in cards),
            inv={}, provider=None, diagram="", scope=""))


# ── Storage devices ────────────────────────────────────────────
@app.get("/storage", response_class=HTMLResponse)
def storage_page(request: Request, refresh: str = ""):
    conns = store.all_stor()
    names = {p_id: p["name"] for p_id, p in store.projects().items()}
    checked = 0
    if refresh and conns:
        # an explicit "check all": run the probes in parallel and store each
        # verdict, so the table is as fresh as the click
        def probe(c):
            ok, detail = stordev.test(c)
            store.update_stor(c.get("pid", ""), c["id"],
                              status=("ok: " if ok else "failed: ") + detail)
            return True
        fleet._pmap(probe, conns, workers=min(6, len(conns)))
        checked = len(conns)
        conns = store.all_stor()

    rows = [{"conn": c, "ok": (c.get("status") or "").startswith("ok"),
             "scope": names.get(c.get("pid") or "", "All projects")}
            for c in conns]
    by_kind: dict = {}
    for c in conns:
        by_kind[c.get("type", "?")] = by_kind.get(c.get("type", "?"), 0) + 1
    return templates.TemplateResponse(
        request, "storage.html",
        ctx(request, conns=conns, rows=rows, providers=stordev.PROVIDERS,
            by_kind=by_kind, checked=checked,
            healthy=sum(1 for r in rows if r["ok"]),
            down=sum(1 for r in rows if r["conn"].get("status")
                     and not r["ok"]),
            never=sum(1 for r in rows if not r["conn"].get("status"))))


@app.post("/storage/{cid}/test")
async def storage_test_one(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    ok, detail = await run_in_threadpool(stordev.test,
                                         store.get_stor(pid, cid) or {})
    store.update_stor(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return RedirectResponse("/storage", 303)


# ── Administration: users, roles, audit ───────────────────────
# Three pages instead of one. Users and roles are things you change; the audit
# log is something you read, often at length — sharing a page made both worse.
@app.get("/users")
def users_legacy():
    """The old combined page. Kept as a redirect so existing links and anyone's
    muscle memory still land somewhere sensible."""
    return RedirectResponse("/admin/users", 307)


def _role_context() -> dict:
    projects = store.projects()
    cluster_names = {}
    for pid, p in projects.items():
        for cid, c in (p.get("clusters") or {}).items():
            cluster_names[cid] = f"{p.get('name', pid)} · {c.get('name', cid)}"
    project_names = {pid: p.get("name", pid) for pid, p in projects.items()}
    # Privileged-Access targets a role can be scoped to — entered targets and
    # every Ansible inventory host, so per-device grants name the same ids the
    # catalogue shows. Grouped by environment so "this host in this env" is a
    # clear pick, not a guess between two same-named rows. target_names is kept
    # (flat) for describe() and any caller that wants the plain label.
    target_names, groups = {}, {}
    for t in pam.targets():
        where = " · ".join(x for x in (t.get("project_name"),
                                       t.get("region_name")) if x)
        label = t["name"] + (f" · {t['address']}" if t.get("address") else "")
        if where:
            label += f"  ({where})"
        target_names[t["id"]] = f"{t['name']} ({t['proto_label']})"
        key = (t.get("env_label") or "Unclassified", t.get("env_tone") or "muted")
        groups.setdefault(key, []).append(
            {"id": t["id"], "label": label, "proto": t["proto_label"]})
    # prod first, then the rest alphabetically, Unclassified last
    order = {"danger": 0, "warn": 1, "accent": 2, "ok": 3, "muted": 9}
    target_groups = [
        {"env": env, "tone": tone,
         "targets": sorted(ts, key=lambda x: x["label"].lower())}
        for (env, tone), ts in sorted(
            groups.items(), key=lambda kv: (order.get(kv[0][1], 5), kv[0][0]))]
    roles = rbac.roles()
    return {"roles": roles, "areas": rbac.AREAS,
            "escalating": rbac.ESCALATING,
            "project_names": project_names, "cluster_names": cluster_names,
            "target_names": target_names, "target_groups": target_groups,
            "counts": rbac.counts(),
            "role_desc": {r["id"]: rbac.describe(r, project_names, cluster_names)
                          for r in roles}}


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, msg: str = "", err: str = "",
                invited: str = "", link: str = "", kind: str = "",
                sent: str = ""):
    if not _may(request, "users"):
        return templates.TemplateResponse(request, "denied.html", ctx(request),
                                          status_code=403)
    users = auth.users()
    rc = _role_context()
    return templates.TemplateResponse(
        request, "admin_users.html",
        ctx(request, users=users,
            user_roles={uid: rbac.of_user(uid) for uid in users},
            # one place decides what "invited", "setting up" and "active" mean,
            # so the badge and the buttons beside it cannot disagree
            states={uid: invite.state(u) for uid, u in users.items()},
            sso_sentinel=auth.SSO_SENTINEL, pending_sentinel=invite.PENDING,
            invited_link=link, invited_user=auth.by_id(invited) if invited else None,
            invited_kind=kind or invite.KIND_INVITE, invited_sent=sent == "1",
            invite_days=invite.RESET_TTL_DAYS if kind == "reset"
            else invite.TTL_DAYS,
            resets=invite.reset_requests(),
            msg=msg, err=err, sso_cfg=sso.config(),
            sso_redirect=_sso_redirect_uri(request),
            sso_msg=request.query_params.get("sso_msg", ""),
            sso_err=request.query_params.get("sso_err", ""), **rc))


@app.get("/admin/roles", response_class=HTMLResponse)
def admin_roles(request: Request, msg: str = "", err: str = ""):
    if not _admin(request):
        return templates.TemplateResponse(request, "denied.html", ctx(request),
                                          status_code=403)
    return templates.TemplateResponse(
        request, "admin_roles.html", ctx(request, msg=msg, err=err, **_role_context()))


@app.post("/admin/roles/save")
async def admin_roles_save(request: Request):
    me = _admin(request)
    if not me:
        return RedirectResponse("/admin/roles?err=admins only", 303)
    f = await request.form()
    name = str(f.get("name", "")).strip()
    if not name:
        return RedirectResponse("/admin/roles?err=a role needs a name", 303)
    areas = f.getlist("areas")
    if not areas:
        return RedirectResponse(
            "/admin/roles?err=" + urllib.parse.quote(
                "tick at least one area — a role granting nothing has no effect"),
            303)
    rid = rbac.save(str(f.get("rid", "")).strip(), name,
                    str(f.get("note", "")), areas,
                    f.getlist("projects"), f.getlist("clusters"),
                    f.getlist("targets"))
    auth.audit(me, "role_saved", name,
               f"{len(areas)} areas", _client_ip(request))
    return RedirectResponse(f"/admin/roles?msg=saved “{name}”#{rid}", 303)


@app.post("/admin/roles/{rid}/delete")
def admin_roles_delete(request: Request, rid: str):
    me = _admin(request)
    if not me:
        return RedirectResponse("/admin/roles?err=admins only", 303)
    role = rbac.get(rid) or {}
    rbac.delete(rid)
    auth.audit(me, "role_deleted", role.get("name", rid), ip=_client_ip(request))
    return RedirectResponse("/admin/roles?msg=role deleted", 303)


@app.post("/admin/users/{uid}/roles")
async def admin_user_roles(request: Request, uid: str):
    me = _may(request, "users")
    if not me:
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    f = await request.form()
    ids = f.getlist("roles")
    # the shortest path to becoming an administrator: assign yourself a role
    # that carries Settings, so it is checked here as well as at creation
    if (why := _guard_user_edit(me, auth.by_id(uid), False, ids)):
        return RedirectResponse(f"/admin/users?err={urllib.parse.quote(why)}", 303)
    rbac.set_for_user(uid, ids)
    who = (auth.by_id(uid) or {}).get("email", uid)
    auth.audit(me, "user_roles_set", who,
               ", ".join((rbac.get(i) or {}).get("name", i) for i in ids)
               or "none", _client_ip(request))
    return RedirectResponse(f"/admin/users?msg=roles updated for {who}#{uid}", 303)


def _audit_until(until: str) -> str:
    """A bare 'YYYY-MM-DD' upper bound means the whole of that day, so the
    stored 'YYYY-MM-DDThh:mm:ss' timestamps on it are not excluded."""
    until = (until or "").strip()
    return until + "T23:59:59" if until and "T" not in until else until


@app.get("/admin/audit", response_class=HTMLResponse)
def admin_audit(request: Request, q: str = "", action: str = "", user: str = "",
                group: str = "", since: str = "", until: str = "",
                page: int = 1, size: int = 100):
    if not _may(request, "audit"):
        return templates.TemplateResponse(request, "denied.html", ctx(request),
                                          status_code=403)
    size = min(max(int(size or 100), 20), 1000)
    page = max(int(page or 1), 1)
    since = (since or "").strip()
    ub = _audit_until(until)
    filt = dict(q=q, action=action, user=user, since=since, until=ub)
    total = auth.count_audit(group=group, **filt)
    pages = max(1, -(-total // size))
    page = min(page, pages)
    rows = auth.read_audit(size, group=group, offset=(page - 1) * size, **filt)
    for r in rows:
        r["sev"] = auth.audit_severity(r["action"])
    # One tile per group, plus a leading Total. Each tile's number is a count
    # under the SAME date/text/user scope, and clicking it applies exactly that
    # group filter — so the number always equals the rows the link then lists.
    tiles = [{"key": "", "label": "All events", "tone": "accent",
              "glyph": "layout-grid",
              "count": auth.count_audit(**filt), "on": not group}]
    for key, (label, tone, glyph, _sql) in auth.AUDIT_GROUPS.items():
        tiles.append({"key": key, "label": label, "tone": tone, "glyph": glyph,
                      "count": auth.count_audit(group=key, **filt),
                      "on": group == key})
    facets = auth.audit_facets()
    ver = auth.verify_audit(limit=1000)          # bounded, fast for the badge
    return templates.TemplateResponse(
        request, "admin_audit.html",
        ctx(request, rows=rows, q=q, action=action, user=user, group=group,
            since=since, until=until, size=size, page=page, pages=pages,
            total=total, tiles=tiles, action_kinds=facets["actions"],
            users=facets["users"], groups=auth.AUDIT_GROUPS, verify=ver,
            msg="", err=""))


@app.get("/admin/audit/verify")
def admin_audit_verify(request: Request, full: int = 0):
    """Re-walk the chain on demand. `full=1` verifies every row from genesis;
    otherwise the recent window, the same bounded check the page badge shows."""
    if not _may(request, "audit"):
        return JSONResponse({"error": "forbidden"}, 403)
    return JSONResponse(auth.verify_audit(limit=0 if full else 1000))


@app.get("/admin/audit/export")
def admin_audit_export(request: Request, q: str = "", action: str = "",
                       user: str = "", group: str = "", since: str = "",
                       until: str = "", limit: int = 5000):
    if not _may(request, "audit"):
        return templates.TemplateResponse(request, "denied.html", ctx(request),
                                          status_code=403)
    rows = auth.read_audit(min(max(int(limit or 5000), 20), 50000), q=q,
                           action=action, user=user, group=group,
                           since=(since or "").strip(), until=_audit_until(until))
    buf = io.StringIO()
    w = csvsafe.writer(buf)
    w.writerow(["at", "user", "action", "target", "detail", "ip"])
    for r in rows:
        w.writerow([r.get(k, "") for k in
                    ("at", "user", "action", "target", "detail", "ip")])
    auth.audit(_may(request, "audit"), "audit_exported", f"{len(rows)} rows",
               ip=_client_ip(request))
    return Response(
        buf.getvalue(), media_type="text/csv",
        headers={"Content-Disposition":
                 'attachment; filename="portal-audit.csv"'})


@app.post("/admin/sso")
async def admin_sso(request: Request):
    me = _admin(request)
    if not me:
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    f = await request.form()
    enabled = bool(f.get("enabled"))
    if f.get("keep"):
        # the switch turned it off: keep every value so it can be switched back
        # on without retyping the application details
        sso.save(enabled=False)
        auth.audit(me, "sso_disabled", "microsoft", ip=_client_ip(request))
        return RedirectResponse("/admin/users?sso_msg="
                                + urllib.parse.quote("Microsoft sign-in turned off"), 303)
    tenant = str(f.get("tenant", "")).strip()
    if enabled and not tenant:
        return RedirectResponse(
            "/admin/users?sso_err=" + urllib.parse.quote(
                "a tenant ID is required to enable Microsoft sign-in"), 303)
    sso.save(enabled=enabled, tenant=tenant,
             client_id=str(f.get("client_id", "")).strip(),
             client_secret=str(f.get("client_secret", "")),
             auto_create=bool(f.get("auto_create")),
             redirect_override=str(f.get("redirect_override", "")).strip())
    auth.audit(me, "sso_settings_saved",
               f"microsoft · {'on' if enabled else 'off'}", ip=_client_ip(request))
    if f.get("do_test"):
        ok, detail = await run_in_threadpool(sso.test, tenant)
        key = "sso_msg" if ok else "sso_err"
        return RedirectResponse(f"/admin/users?{key}="
                                + urllib.parse.quote(detail), 303)
    return RedirectResponse("/admin/users?sso_msg="
                            + urllib.parse.quote("Microsoft sign-in saved"), 303)


@app.post("/admin/users/new")
async def admin_users_new(request: Request):
    if not _may(request, "users"):
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    f = await request.form()
    email = str(f.get("email", "")).strip().lower()
    pw = str(f.get("password", ""))
    if "@" not in email:
        return RedirectResponse("/admin/users?err=enter a valid email address", 303)
    if (problem := auth.password_problem(pw)):
        return RedirectResponse(f"/admin/users?err={problem}", 303)
    me = _may(request, "users")
    if (why := _guard_user_edit(me, None, str(f.get("role", "")) == "admin",
                                f.getlist("roles"))):
        return RedirectResponse(f"/admin/users?err={urllib.parse.quote(why)}", 303)
    try:
        uid = auth.create_user(email, str(f.get("name", "")), pw,
                               role=str(f.get("role", "user")))
    except ValueError as e:
        return RedirectResponse(f"/admin/users?err={e}", 303)
    rbac.set_for_user(uid, f.getlist("roles"))
    auth.audit(_may(request, "users"), "user_created", email, ip=_client_ip(request))
    return RedirectResponse(
        "/admin/users?msg=" + urllib.parse.quote(
            f"created {email} — they set up Google Authenticator at first login"),
        303)


@app.post("/admin/users/{uid}/update")
async def admin_users_update(request: Request, uid: str):
    me = _may(request, "users")
    if not me:
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    f = await request.form()
    fields = {"name": str(f.get("name", "")).strip(),
              "role": str(f.get("role", "user")),
              "disabled": f.get("disabled") == "on"}
    if (why := _guard_user_edit(me, auth.by_id(uid),
                                fields["role"] == "admin", [])):
        return RedirectResponse(f"/admin/users?err={urllib.parse.quote(why)}", 303)
    if uid == me["id"] and (fields["disabled"] or fields["role"] != "admin"):
        return RedirectResponse(
            "/admin/users?err=" + urllib.parse.quote(
                "you cannot remove your own admin access or disable yourself"), 303)
    auth.update_user(uid, **fields)
    if str(f.get("password", "")):
        problem = auth.password_problem(str(f.get("password")))
        if problem:
            return RedirectResponse(f"/admin/users?err={problem}", 303)
        auth.set_password(uid, str(f.get("password")))
        auth.audit(me, "password_reset", (auth.by_id(uid) or {}).get("email", uid),
                   ip=_client_ip(request))
    auth.audit(me, "user_updated", (auth.by_id(uid) or {}).get("email", uid),
               ip=_client_ip(request))
    return RedirectResponse("/admin/users?msg=user updated", 303)


# ── invitations ────────────────────────────────────────────────
# An account nobody has claimed has no password at all. The person who opens
# the link chooses one, and opening it is what proves they hold the address.
def _origin(request: Request) -> str:
    """Where to build a link the ADMIN will see in their own browser.

    The Host header is fine here: the administrator asked for this page, and a
    link built from the address they are already looking at is the one that
    works for them. It is not fine for a link that gets emailed — see
    _mail_origin.
    """
    configured = mailer.public_base()
    if configured:
        return configured + (env.ROOT_PATH or "")
    base = str(request.base_url).rstrip("/")
    return base + (env.ROOT_PATH or "")


def _mail_origin() -> str:
    """Where to build a link that will be POSTED TO SOMEBODY. "" if unknown.

    Deliberately takes no request. request.base_url is the Host header, and
    /forgot is open to anonymous callers: anybody could send a reset request
    with a forged Host and the victim would receive a genuine reset link
    pointing at the attacker's server. The recipient of these links is not the
    person who made the request, so the address cannot come from the request.

    Unset means no emailed links at all — the caller falls back to handing the
    link to an administrator, which is the behaviour with no relay anyway.
    """
    base = mailer.public_base()
    return (base + (env.ROOT_PATH or "")) if base else ""


def _deliver(kind: str, user: dict, token: str, request: Request,
             clear_mfa: bool = False) -> tuple[str, str]:
    """Post the link if we can. Returns (how, what to tell the admin).

    "how" is recorded on the invitation and decides whether accepting it counts
    as verifying the address — see invite.py. A relay that fails does not lose
    the invitation: the link falls back to being shown, marked as hand-carried.
    """
    if not mailer.configured():
        return "manual", ""
    origin = _mail_origin()
    if not origin:
        # refusing to guess: a link built from the request's Host header and
        # then emailed is how a reset gets poisoned
        return "manual", ("no public address is set, so the link in the email "
                          "would be built from the request's Host header — set "
                          "PORTAL_BASE_URL, or the address in Settings → Email")
    link = invite.link(origin, token, kind)
    days = (invite.RESET_TTL_DAYS if kind == invite.KIND_RESET
            else invite.TTL_DAYS)
    if kind == invite.KIND_RESET:
        subject, body = mailer.reset(user.get("name") or "", link,
                                     store.brand()["name"], days, clear_mfa)
    else:
        subject, body = mailer.invitation(user.get("name") or "", link,
                                          store.brand()["name"], days)
    try:
        mailer.send(user["email"], subject, body)
    except ValueError as e:
        return "manual", str(e)
    return "email", ""


@app.post("/admin/users/invite")
async def admin_users_invite(request: Request):
    me = _may(request, "users")
    if not me:
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    f = await request.form()
    email = str(f.get("email", "")).strip().lower()
    if "@" not in email:
        return RedirectResponse("/admin/users?err=enter a valid email address", 303)
    if (why := _guard_user_edit(me, None, str(f.get("role", "")) == "admin",
                                f.getlist("roles"))):
        return RedirectResponse(f"/admin/users?err={urllib.parse.quote(why)}", 303)
    try:
        uid = invite.create_user(email, str(f.get("name", "")),
                                 role=str(f.get("role", "user")))
    except ValueError as e:
        return RedirectResponse(f"/admin/users?err={e}", 303)
    rbac.set_for_user(uid, f.getlist("roles"))
    token = invite.issue(uid, me.get("email", ""))
    how, why = _deliver(invite.KIND_INVITE, auth.by_id(uid), token, request)
    invite.mark_delivery(uid, invite.KIND_INVITE, how)
    auth.audit(me, "user_invited", email,
               f"role {f.get('role', 'user')} · {how}", _client_ip(request))
    # The link is shown either way. Emailing it does not mean nobody needs to
    # see it: mail is slow, mail is filtered, and the person asking "did it
    # arrive?" is standing next to you. Only its hash is stored, so this is the
    # single moment it can be shown at all.
    return RedirectResponse(
        f"/admin/users?invited={uid}&sent={1 if how == 'email' else 0}"
        f"&link={urllib.parse.quote(invite.link(_mail_origin() or _origin(request), token))}"
        + (f"&err={urllib.parse.quote('could not email it: ' + why)}" if why else ""),
        303)


@app.post("/admin/users/{uid}/invite")
def admin_users_reinvite(request: Request, uid: str):
    me = _may(request, "users")
    if not me:
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    u = auth.by_id(uid)
    if not u:
        return RedirectResponse("/admin/users?err=no such user", 303)
    token = invite.issue(uid, me.get("email", ""))
    how, why = _deliver(invite.KIND_INVITE, u, token, request)
    invite.mark_delivery(uid, invite.KIND_INVITE, how)
    auth.audit(me, "user_reinvited", u["email"], how, _client_ip(request))
    return RedirectResponse(
        f"/admin/users?invited={uid}&sent={1 if how == 'email' else 0}"
        f"&link={urllib.parse.quote(invite.link(_mail_origin() or _origin(request), token))}"
        + (f"&err={urllib.parse.quote('could not email it: ' + why)}" if why else ""),
        303)


@app.post("/admin/users/{uid}/invite/revoke")
def admin_users_revoke_invite(request: Request, uid: str):
    me = _may(request, "users")
    if not me:
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    live = invite.outstanding(uid)
    if live:
        invite.revoke(live["id"])
    u = auth.by_id(uid) or {}
    auth.audit(me, "invite_revoked", u.get("email", uid), ip=_client_ip(request))
    return RedirectResponse(
        "/admin/users?msg=" + urllib.parse.quote(
            "invitation revoked — the link no longer works"), 303)


# ── forgotten passwords ────────────────────────────────────────
# There is no mail sender here, and there must not be a way for whoever types
# an address into this form to be handed a link for it — that would let anybody
# reset anybody's password. So the request is recorded and an administrator
# hands over the link, exactly as they do for an invitation.
@app.get("/forgot", response_class=HTMLResponse)
def forgot_form(request: Request, sent: str = "", err: str = ""):
    return templates.TemplateResponse(
        request, "forgot.html", {"request": request, "status": None, "err": err,
                        "sent": bool(sent), "brand": store.brand})


@app.post("/forgot")
async def forgot_submit(request: Request):
    f = await request.form()
    email = str(f.get("email", "")).strip().lower()
    who = auth.by_email(email)
    sent = False
    if who and not who.get("disabled") and not invite.is_pending(who) \
            and mailer.configured():
        # With a relay there is no reason to route this through a person: the
        # link goes to the address itself, which is the only place it is safe
        # to send it. Without one it is recorded for an administrator instead.
        token = invite.issue(who["id"], "self-service", kind=invite.KIND_RESET)
        how, _why = _deliver(invite.KIND_RESET, who, token, request)
        invite.mark_delivery(who["id"], invite.KIND_RESET, how)
        sent = how == "email"
    if not sent:
        invite.request_reset(email, _client_ip(request))
    auth.audit({"email": email or "?"}, "password_reset_requested", email,
               "emailed" if sent else "queued for an administrator",
               _client_ip(request))
    # the same answer either way: a different one for an address that exists
    # turns this form into a way to find out who has an account here
    return RedirectResponse("/forgot?sent=1", 303)


@app.post("/admin/users/{uid}/reset-link")
def admin_users_reset_link(request: Request, uid: str):
    me = _may(request, "users")
    if not me:
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    u = auth.by_id(uid)
    if not u:
        return RedirectResponse("/admin/users?err=no such user", 303)
    if invite.is_pending(u):
        return RedirectResponse(
            "/admin/users?err=" + urllib.parse.quote(
                "that account has never been claimed — send an invitation "
                "rather than a reset"), 303)
    # An administrator issuing this has identified the person some other way,
    # and a lost password usually arrives with a lost phone. Self-service
    # resets do not do this — see invite.accept.
    token = invite.issue(uid, me.get("email", ""), kind=invite.KIND_RESET,
                         clear_mfa=True)
    how, why = _deliver(invite.KIND_RESET, u, token, request, clear_mfa=True)
    invite.mark_delivery(uid, invite.KIND_RESET, how)
    auth.audit(me, "password_reset_issued", u["email"], how, _client_ip(request))
    return RedirectResponse(
        f"/admin/users?invited={uid}&kind=reset&sent={1 if how == 'email' else 0}"
        f"&link={urllib.parse.quote(invite.link(_mail_origin() or _origin(request), token, invite.KIND_RESET))}"
        + (f"&err={urllib.parse.quote('could not email it: ' + why)}" if why else ""),
        303)


@app.post("/admin/resets/{rid}/dismiss")
def admin_reset_dismiss(request: Request, rid: str):
    me = _may(request, "users")
    if not me:
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    invite.dismiss_request(rid)
    return RedirectResponse("/admin/users?msg=request dismissed", 303)


@app.get("/reset/{token}", response_class=HTMLResponse)
def reset_open(request: Request, token: str, err: str = ""):
    got = invite.check(token, invite.KIND_RESET)
    return templates.TemplateResponse(
        request, "reset.html",
        {"request": request, "status": None, "err": err, "ok": got["ok"],
         "why": got["why"], "token": token, "who": got["user"],
         "clear_mfa": bool((got["invite"] or {}).get("clear_mfa")),
         "brand": store.brand},
        status_code=200 if got["ok"] else 410)


@app.post("/reset/{token}")
async def reset_submit(request: Request, token: str):
    f = await request.form()
    pw = str(f.get("password", ""))
    if pw != str(f.get("confirm", "")):
        return RedirectResponse(
            f"/reset/{token}?err=" + urllib.parse.quote(
                "the two passwords do not match"), 303)
    try:
        u = invite.accept(token, pw, invite.KIND_RESET)
    except ValueError as e:
        return RedirectResponse(
            f"/reset/{token}?err={urllib.parse.quote(str(e))}", 303)
    auth.audit(u, "password_reset", u["email"],
               "authenticator cleared too" if not u.get("mfa_enrolled") else "",
               _client_ip(request))
    # deliberately no session: the new password still has to be presented at
    # the sign-in page along with an authenticator code, or a reset link would
    # be a way round the second factor
    return RedirectResponse(
        "/login?err=" + urllib.parse.quote(
            "Password changed — sign in with it and your authenticator code."),
        303)


@app.get("/invite/{token}", response_class=HTMLResponse)
def invite_open(request: Request, token: str, err: str = ""):
    # the kind matters: a reset token opened here would show somebody an
    # "accept your invitation" page for an account they already have
    got = invite.check(token, invite.KIND_INVITE)
    return templates.TemplateResponse(
        request, "invite.html",
        {"request": request, "status": None if got["ok"] else 410,
         "err": err, "ok": got["ok"], "why": got["why"], "token": token,
         "who": got["user"], "brand": store.brand,
         "roles": rbac.of_user(got["user"]["id"]) if got["user"] else []},
        status_code=200 if got["ok"] else 410)


@app.post("/invite/{token}")
async def invite_accept(request: Request, token: str):
    f = await request.form()
    pw = str(f.get("password", ""))
    if pw != str(f.get("confirm", "")):
        return RedirectResponse(
            f"/invite/{token}?err=" + urllib.parse.quote(
                "the two passwords do not match"), 303)
    try:
        u = invite.accept(token, pw, invite.KIND_INVITE)
    except ValueError as e:
        return RedirectResponse(
            f"/invite/{token}?err={urllib.parse.quote(str(e))}", 303)
    # straight into enrolment: signed in as far as the password goes, and the
    # session is not usable for anything until a code is confirmed
    request.session.update({"uid": u["id"], "mfa_ok": False, "next": "/"})
    auth.audit(u, "invite_accepted", u["email"], "email verified",
               _client_ip(request))
    return RedirectResponse("/mfa/setup", 303)


@app.post("/admin/users/{uid}/reset-mfa")
def admin_users_reset_mfa(request: Request, uid: str):
    me = _may(request, "users")
    if not me:
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    auth.reset_mfa(uid)
    auth.audit(me, "mfa_reset", (auth.by_id(uid) or {}).get("email", uid),
               ip=_client_ip(request))
    return RedirectResponse(
        "/admin/users?msg=" + urllib.parse.quote(
            "MFA reset — they will re-enrol at next login"), 303)


@app.post("/admin/users/{uid}/delete")
async def admin_users_delete(request: Request, uid: str):
    me = _may(request, "users")
    if not me:
        return RedirectResponse(
            "/admin/users?err=your roles do not include User accounts", 303)
    if uid == me["id"]:
        return RedirectResponse(
            "/admin/users?err=you cannot delete your own account", 303)
    # The word is required here, not only in the dialog. A confirmation that
    # lives in the browser is a confirmation anybody can skip with one request,
    # and this is the endpoint that takes an account and its roles away.
    f = await request.form()
    if str(f.get("confirm", "")).strip().casefold() != "delete":
        return RedirectResponse(
            "/admin/users?err=" + urllib.parse.quote(
                "type Delete to remove an account"), 303)
    target = auth.by_id(uid)
    if (why := _guard_user_edit(me, target, False, [])):
        return RedirectResponse(f"/admin/users?err={urllib.parse.quote(why)}", 303)
    email = (target or {}).get("email", uid)
    auth.delete_user(uid)
    rbac.set_for_user(uid, [])
    # A bearer token outliving its owner is a credential with nobody
    # accountable for it — and it would keep answering as a user who is gone.
    mcp.drop_for_user(uid)
    # Same reasoning for a passkey. The login route looks the account up from
    # the credential and refuses a missing one, so an orphan cannot sign in —
    # but leaving rows keyed to a deleted account means the next person given
    # that email inherits nothing and the table grows credentials nobody owns.
    passkeys.drop_all(uid)
    auth.audit(me, "user_deleted", email, ip=_client_ip(request))
    return RedirectResponse("/admin/users?msg=user removed", 303)


# ── refuse to serve beyond localhost unless explicitly allowed ──
@app.get("/healthz")
def healthz():
    """Liveness and readiness for the container and the chart.

    Deliberately shallow: it says the process is serving, not that every cluster
    is reachable. A probe that fails because someone else's cluster is down would
    restart a portal that is working perfectly.
    """
    return JSONResponse({"status": "ok", "version": env.VERSION})


@app.on_event("startup")
def _start_warmer() -> None:
    """Keep the caches full so no page is ever the cold one — app/warmer.py."""
    warmer.start()


@app.on_event("startup")
def _check_tools():
    """Fail fast and clearly when kubectl or git is missing from the image."""
    import logging
    log = logging.getLogger("uvicorn.error")
    tools.verify_or_die()
    found = [f"{t['name']} {t['version']}" for t in tools.check() if t["found"]]
    # The provisioning engine is resolved by terraform.tool(), not by the tools
    # registry: it already picks between PORTAL_TERRAFORM, terraform and tofu
    # and caches the answer, and a second probe beside it would be a second
    # opinion that can disagree with the page. Named at startup because the
    # image now ships OpenTofu and "which engine planned this" is otherwise
    # invisible until a stack behaves differently on two installs.
    tf = terraform.tool()
    if tf.get("found"):
        found.append(tf["version"].split(" on ")[0].strip() or "terraform")
    log.info("config portal %s · %s", env.VERSION,
             ", ".join(found) or "no tools found")
    for t in tools.check():
        if not t["found"]:
            log.warning("%s is unavailable (%s) — %s will not work",
                        t["name"], t["error"], t["purpose"])


@app.on_event("startup")
def _warm_clouds():
    """Cloud inventory is collected in the background from startup, so the
    Clouds page shows numbers rather than a spinner."""
    cloud.warm_start()


@app.on_event("startup")
def _carry_certificates():
    """Pick up every certificate order still in flight.

    This is what makes the certificates page closable: an order's state is a row,
    and this is the thing that moves it. Started unconditionally, because the
    orders that most need carrying are the ones that were in progress when the
    pod was replaced.
    """
    certs.start_worker()


@app.on_event("startup")
def _close_orphan_runs():
    """A playbook run whose portal was replaced mid-play is not still running.

    Without this the row says `running` for ever: the page shows a spinner that
    never stops, and the playbook cannot be started again because the portal
    believes one is already going. What actually happened on the hosts is not
    knowable from here, so the run says exactly that rather than claiming a
    result.
    """
    import logging
    closed = ansible.adopt_orphans()
    if closed:
        logging.getLogger("uvicorn.error").warning(
            "closed %d ansible run(s) left open by a restart", closed)
    terraform.adopt_orphans()      # same sweep for terraform runs


@app.on_event("startup")
def _start_scheduler():
    """The schedule ticker. After the orphan sweep, so a run left open by a
    restart is closed before the ticker can decide the same playbook is
    'already running' and skip a fire it should have made."""
    ansible.scheduler_start()


@app.on_event("startup")
def _warm_logs():
    """The log-store warmer starts with the app, so the first person to open
    the Logs page after a deploy sees numbers, not a spinner."""
    logstore.warm_start()


@app.on_event("startup")
def _guard_binding():
    """This process holds git tokens, kubeconfigs and sealing keys. Serving it on
    a shared interface without deliberate intent is the failure mode to prevent,
    so require PORTAL_ALLOW_NETWORK=1 for any non-loopback bind."""
    import sys
    host = env.HOST
    if not host:
        argv = " ".join(sys.argv)
        for token in ("--host=", "--host "):
            if token in argv:
                host = argv.split(token, 1)[1].split()[0]
                break
    loopback = host in ("", "127.0.0.1", "localhost", "::1")
    if not loopback and not env.ALLOW_NETWORK:
        raise RuntimeError(
            f"refusing to bind {host}: the portal stores git tokens, kubeconfigs "
            "and sealing certificates. Put it behind an authenticating reverse "
            "proxy on the internal network, then set PORTAL_ALLOW_NETWORK=1.")


# ── pipelines (display only — configuration lives in Settings) ──
@app.get("/pipelines/stages")
async def pipeline_stages(request: Request, conn: str = "", ref: str = "",
                          refresh: str = ""):
    """The stages of one run, as JSON, fetched when a row is opened.

    A separate request on purpose: a stage list is one API call per run, so
    fetching them all with the table would turn a fourteen-row page into fifteen
    calls before anyone clicked anything — rate limit spent on information nobody
    asked for. Failing rows are the exception and the page asks for those itself.
    """
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "pipelines"):
        return JSONResponse({"error": "your roles do not include pipelines"},
                            status_code=403)
    sel = next((c for c in store.all_ci() if c["id"] == conn), None)
    if not sel:
        return JSONResponse({"error": "unknown connection"}, status_code=404)
    if not rbac.may_project(me, sel.get("pid") or ""):
        return JSONResponse({"error": "your roles do not include that project"},
                            status_code=403)
    got = await run_in_threadpool(ci.stages, sel, ref, bool(refresh))
    return JSONResponse(got)


@app.get("/pipelines/logs", response_class=HTMLResponse)
def pipeline_logs(request: Request, conn: str = "", ref: str = "",
                  job: str = "", refresh: str = ""):
    """One job's build output, read here rather than on the provider.

    The stage strip says where a build broke; this says why, which is the next
    question every single time and used to mean leaving the portal, finding
    the run again and expanding the right job.
    """
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "pipelines"):
        raise HTTPException(403)
    sel = next((c for c in store.all_ci() if c["id"] == conn), None)
    if not sel or not ref:
        return RedirectResponse("/pipelines", 303)
    if not rbac.may_project(me, sel.get("pid") or ""):
        raise HTTPException(403)
    # only what can be shown at once; the text arrives on its own request
    shell = ci.log_shell(sel, ref, job)
    # only if it is already known: this is the page heading, and collecting a
    # whole owner's pipelines to spell it took five seconds off the load
    listed = ci.peek(sel) or {}
    run = next((r for r in listed.get("jobs", []) if r.get("ref") == ref), None)
    return templates.TemplateResponse(
        request, "pipeline_logs.html",
        ctx(request, conn=sel, ref=ref, log=shell, providers=ci.PROVIDERS,
            max_bytes=ci.LOG_BYTES,
            title=(run or {}).get("name") or ref.split("#")[0],
            run_status=(run or {}).get("status", "")))


@app.get("/pipelines/logs/body", response_class=HTMLResponse)
def pipeline_log_body(request: Request, conn: str = "", ref: str = "",
                      job: str = "", refresh: str = ""):
    """The log text, fetched after the page is on screen.

    Two and a half seconds of that is the provider handing over the file, and
    staring at nothing for it is the difference between "slow" and "loading".
    """
    me = getattr(request.state, "user", None)
    if not rbac.may_area(me, "pipelines"):
        raise HTTPException(403)
    sel = next((c for c in store.all_ci() if c["id"] == conn), None)
    if not sel or not ref:
        return HTMLResponse("", status_code=404)
    if not rbac.may_project(me, sel.get("pid") or ""):
        raise HTTPException(403)
    got = ci.log(sel, ref, job, bool(refresh))
    auth.audit(me, "pipeline_log", f"{sel.get('name', conn)}:{ref}",
               (got.get("job") or {}).get("name", ""), _client_ip(request))
    return templates.TemplateResponse(
        request, "pipeline_log_body.html",
        ctx(request, log=got, max_bytes=ci.LOG_BYTES))


@app.get("/pipelines", response_class=HTMLResponse)
def pipelines_page(request: Request, provider: str = "", conn: str = "",
                   only: str = "", q: str = "", view: str = "", sec: str = "",
                   refresh: str = "", msg: str = "", err: str = ""):
    """Three levels off one route:
         /pipelines                        → a box per CI provider in use
         ?provider=jenkins                 → a box per connection of that kind
         ?provider=jenkins&conn=<id>       → the pipeline table
    Only the connections the current level actually needs are fetched, so
    drilling in gets cheaper rather than more expensive."""
    from concurrent.futures import ThreadPoolExecutor
    conns = store.all_ci()
    names = {p_id: p["name"] for p_id, p in store.projects().items()}
    if refresh:
        ci.invalidate()

    def scope_of(c):
        return names.get(c.get("pid") or "", "All projects")

    # providers are derived from what is connected, never hardcoded, so a box
    # appears the moment a connection of that type exists and vanishes with it
    present = [k for k in ci.PROVIDERS if any(c.get("type") == k for c in conns)]
    if provider and provider not in present:
        provider = ""
    sel = next((c for c in conns if c["id"] == conn), None) if conn else None
    if sel and provider and sel.get("type") != provider:
        sel = None
    level = "detail" if sel else ("provider" if provider else "hub")

    need = ([sel] if level == "detail"
            else [c for c in conns if c.get("type") == provider] if level == "provider"
            else conns)

    def pull(c):
        try:
            got = ci.fetch(c)
            return (c, got["jobs"], got["views"], "")
        except Exception as e:                                # noqa: BLE001
            return (c, [], [], str(e)[:220])

    fetched = []
    if need:
        with ThreadPoolExecutor(max_workers=min(6, len(need))) as pool:
            fetched = list(pool.map(pull, need))
    by_id = {c["id"]: (rows, vs, e) for c, rows, vs, e in fetched}

    cards, groups, views = [], [], []
    all_jobs = [r for _c, rows, _v, _e in fetched for r in rows]

    if level == "hub":
        for key in present:
            mine = [c for c in conns if c.get("type") == key]
            rows = [r for c in mine for r in by_id.get(c["id"], ([], [], ""))[0]]
            broken = [c for c in mine if by_id.get(c["id"], ([], [], ""))[2]]
            cards.append({
                "key": key, "provider": ci.PROVIDERS[key], "conns": mine,
                "jobs": len(rows), "totals": ci.summarise(rows),
                "broken": len(broken),
                "href": f"/pipelines?provider={key}",
            })
        # every connection's pipelines, one group each, so the Overview's
        # All / Running / Failed tabs triage the whole estate without drilling in
        # (nothing extra is fetched — hub already pulled every connection)
        for c in conns:
            rows, _vs, error = by_id.get(c["id"], ([], [], ""))
            groups.append({
                "conn": c, "rows": sorted(rows, key=lambda r: r["name"].lower()),
                "error": error, "total": len(rows), "scope": scope_of(c),
                "provider": ci.PROVIDERS.get(c.get("type"), {}),
            })

    elif level == "provider":
        for c in [x for x in conns if x.get("type") == provider]:
            rows, vs, error = by_id.get(c["id"], ([], [], ""))
            cards.append({
                "conn": c, "provider": ci.PROVIDERS.get(provider, {}),
                "jobs": len(rows), "totals": ci.summarise(rows),
                "views": len(vs), "error": error, "scope": scope_of(c),
                "href": f"/pipelines?provider={provider}&conn={c['id']}",
            })

    else:                                       # detail — one connection
        rows, views, error = by_id.get(sel["id"], ([], [], ""))
        shown = rows
        if view:
            shown = [r for r in shown if view in (r.get("views") or [])]
        if only == "failed":
            shown = [r for r in shown if r["status"] == "failed"]
        elif only == "running":
            shown = [r for r in shown if r["status"] == "running"]
        if q:
            shown = [r for r in shown if q.lower() in r["name"].lower()]
        groups.append({
            "conn": sel, "rows": sorted(shown, key=lambda r: r["name"].lower()),
            "error": error, "total": len(rows), "scope": scope_of(sel),
            "provider": ci.PROVIDERS.get(sel.get("type"), {}),
        })

    return templates.TemplateResponse(
        request, "pipelines.html",
        ctx(request, level=level, cards=cards, groups=groups, conns=conns,
            views=views, present=present, providers=ci.PROVIDERS,
            provider=provider, sel=sel, sec=sec,
            totals=ci.summarise(all_jobs), total=len(all_jobs),
            only=only, q=q, conn=conn, view=view, msg=msg, err=err))


# ── CI connection management (Settings) ────────────────────────
def _ci_from_form(f) -> dict:
    return {"skip_tls": f.get("skip_tls") == "on",
            "type": str(f.get("type", "")).strip(),
            "name": str(f.get("name", "")).strip(),
            "base_url": str(f.get("base_url", "")).strip().rstrip("/"),
            "repo": str(f.get("repo", "")).strip(),
            "project": str(f.get("project", "")).strip(),
            "folder": str(f.get("folder", "")).strip(),
            "username": str(f.get("username", "")).strip()}


@app.post("/settings/ci/new")
async def ci_new(request: Request):
    f = await request.form()
    conn = _ci_from_form(f)
    conn["token"] = str(f.get("token", ""))
    pid = str(f.get("pid", ""))
    if conn["type"] not in ci.PROVIDERS:
        return back(err="choose a CI provider", to="/settings/pipelines")
    if not conn["name"]:
        conn["name"] = ci.PROVIDERS[conn["type"]]["label"]
    missing = [k for k in ci.PROVIDERS[conn["type"]]["needs"] if not conn.get(k)]
    if missing:
        return back(err=f"missing for {ci.PROVIDERS[conn['type']]['label']}: "
                        f"{', '.join(missing)}", to="/settings/pipelines")
    ok, detail = await run_in_threadpool(ci.test, conn)
    conn["status"] = ("ok: " if ok else "failed: ") + detail
    store.add_ci(pid, conn)
    auth.audit(getattr(request.state, "user", None), "ci_connected",
               f"{conn['type']}:{conn['name']}", detail, _client_ip(request))
    return (back(msg=f"{conn['name']} — {detail}", to="/settings/pipelines")
            if ok else back(err=detail, to="/settings/pipelines"))


@app.post("/settings/ci/{cid}/update")
async def ci_update(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    fields = _ci_from_form(f)
    fields.pop("type", None)
    if str(f.get("token", "")):
        fields["token"] = str(f.get("token"))
    store.update_ci(pid, cid, **fields)
    ci.invalidate()
    ok, detail = await run_in_threadpool(ci.test, store.get_ci(pid, cid) or {})
    store.update_ci(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/pipelines") if ok
            else back(err=detail, to="/settings/pipelines"))


@app.post("/settings/ci/{cid}/test")
async def ci_test(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    ok, detail = await run_in_threadpool(ci.test, store.get_ci(pid, cid) or {})
    store.update_ci(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/pipelines") if ok
            else back(err=detail, to="/settings/pipelines"))


@app.post("/settings/ci/{cid}/delete")
async def ci_delete(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    name = (store.get_ci(pid, cid) or {}).get("name", cid)
    store.delete_ci(pid, cid)
    ci.invalidate()
    auth.audit(getattr(request.state, "user", None), "ci_removed", name,
               ip=_client_ip(request))
    return back(msg="connection removed", to="/settings/pipelines")


# ── security scanning (display only — configuration lives in Settings) ──
@app.get("/security", response_class=HTMLResponse)
def security_page(request: Request, platform: str = "", conn: str = "",
                  product: str = "", tab: str = "products", sev: str = "",
                  q: str = "", group: str = "", offset: int = 0,
                  finding: str = "", status: str = "", refresh: str = "",
                  msg: str = "", err: str = ""):
    """Four levels off one route, mirroring /pipelines:
         /security                              → a box per scan platform in use
         ?platform=defectdojo                   → a box per connection
         ?platform=…&conn=<id>                  → products / findings / scans
         ?platform=…&conn=<id>&product=<pid>    → one product, exact severities
    Each level pulls only the part it renders — see security.py for why."""
    from concurrent.futures import ThreadPoolExecutor
    conns = store.all_sec()
    names = {p_id: p["name"] for p_id, p in store.projects().items()}
    fresh = bool(refresh)
    if fresh:
        security.invalidate()

    present = [k for k in security.PROVIDERS
               if any(c.get("type") == k for c in conns)]
    if platform and platform not in present:
        platform = ""
    sel = next((c for c in conns if c["id"] == conn), None) if conn else None
    if sel and platform and sel.get("type") != platform:
        sel = None
    level = ("product" if sel and product else "detail" if sel
             else "provider" if platform else "hub")

    cards, block, prod, sonar = [], None, None, None
    totals, n_products = security._blank(), 0
    findings_head = None       # detail level: the connection-wide open count,
                               # for the head, while `totals` follows the scope

    if level in ("hub", "provider"):
        # boxes need portfolio counts only — the cheapest part there is
        need = (conns if level == "hub"
                else [c for c in conns if c.get("type") == platform])

        def over(c):
            try:
                return (c, security.overview(c), "")
            except Exception as e:                            # noqa: BLE001
                return (c, None, str(e)[:220])

        got = []
        if need:
            with ThreadPoolExecutor(max_workers=min(4, len(need))) as pool:
                got = list(pool.map(over, need))
        by_id = {c["id"]: (o, e) for c, o, e in got}
        totals = security.merge_totals([o for _c, o, _e in got if o])
        n_products = sum((o or {}).get("products", 0) for _c, o, _e in got)

        if level == "hub":
            for key in present:
                mine = [c for c in conns if c.get("type") == key]
                obs = [by_id.get(c["id"], (None, ""))[0] for c in mine]
                cards.append({
                    "key": key, "provider": security.PROVIDERS[key], "conns": mine,
                    "totals": security.merge_totals([o for o in obs if o]),
                    "products": sum((o or {}).get("products", 0) for o in obs),
                    "broken": sum(1 for c in mine if by_id.get(c["id"], (None, ""))[1]),
                    "href": f"/security?platform={key}",
                })
        else:
            for c in [x for x in conns if x.get("type") == platform]:
                o, error = by_id.get(c["id"], (None, ""))
                cards.append({
                    "conn": c, "provider": security.PROVIDERS.get(platform, {}),
                    "totals": (o or {}).get("totals") or security._blank(),
                    "products": (o or {}).get("products", 0),
                    "open": (o or {}).get("open", 0), "error": error,
                    "scope": names.get(c.get("pid") or "", "All projects"),
                    "href": f"/security?platform={platform}&conn={c['id']}",
                })

    elif level == "detail":
        size = security.page_size(sel)
        block = {"conn": sel, "error": "", "products": [], "findings": None,
                 "scans": [], "groups": [], "note": "",
                 "scope": names.get(sel.get("pid") or "", "All projects"),
                 "provider": security.PROVIDERS.get(sel.get("type"), {})}
        # Every part of a tab is an independent, independently-cached read, so
        # they are fetched TOGETHER. A cold findings view is five separate
        # network waits (overview counts, severity counts, the product/group
        # pull, the findings page, the status counts) and paying them one after
        # another is what made this page slow — parallel, it costs the slowest
        # one. The `finding` id is validated before anything is submitted.
        jobs = {"over": lambda: security.overview(sel)}
        if tab == "findings":
            jobs["sevs"] = lambda: security.sev_counts(
                sel, refresh=bool(refresh), q=q, group=group, status=status)
            jobs["groups"] = lambda: security.groups(sel)
            jobs["page"] = lambda: security.findings(
                sel, limit=size, offset=max(0, offset), sev=sev, q=q,
                group=group, status=status)
            # the lifecycle strip above the list: open, closed and why — each
            # an exact count IN THE SAME SCOPE as the list, so a tab is a
            # promise, not a guess
            jobs["statuses"] = lambda: security.status_counts(
                sel, refresh=bool(refresh), sev=sev, q=q, group=group)
            if finding:
                try:
                    fid = int(finding)
                    jobs["finding"] = lambda: security.finding(
                        sel, fid, refresh=bool(refresh))
                except (ValueError, TypeError):
                    block["finding_err"] = "that finding id is not a number"
        elif tab == "scans":
            jobs["scans"] = lambda: security.scans(sel)
        else:
            jobs["products"] = lambda: security.products(sel)
            jobs["statuses"] = lambda: security.status_counts(
                sel, refresh=bool(refresh), group=group)
            if group:
                jobs["sevs"] = lambda: security.sev_counts(
                    sel, refresh=bool(refresh), group=group)
        with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            futs = {k: pool.submit(fn) for k, fn in jobs.items()}
        res = {}
        for k, fut in futs.items():
            try:
                res[k] = fut.result()
            except Exception as e:                            # noqa: BLE001
                # the opened finding fails alone (a bad id or a hiccup must not
                # take the list down); anything else is the page's error
                if k == "finding":
                    block["finding_err"] = str(e)[:220]
                elif not block["error"]:
                    block["error"] = str(e)[:220]

        o = res.get("over")
        if o:
            totals, n_products = o["totals"], o["products"]
            # the page-head keeps the connection's identity (all open, all
            # products); every figure BELOW it follows the page's own scope
            findings_head = sum(totals.values())
            block["note"] = o.get("note", "")
        if tab == "findings":
            # ONE scope for the whole view: the severity tiles count the same
            # group + status + search as the strip and the list under them —
            # "CRITICAL 15,113" must never sit above a list of 109
            if "sevs" in res:
                totals = res["sevs"]
            block["groups"] = res.get("groups") or []
            block["findings"] = res.get("page")
            block["statuses"] = res.get("statuses")
            block["finding"] = res.get("finding")
        elif tab == "scans":
            block["scans"] = res.get("scans") or []
        elif "products" in res:
            rows = res["products"]
            block["statuses"] = res.get("statuses")
            if group and "sevs" in res:
                totals = res["sevs"]
            block["groups"] = sorted({p["group"] for p in rows if p.get("group")})
            if group:
                rows = [p for p in rows if p.get("group") == group]
            # Severity is a property of findings, not of products. Platforms
            # that report a per-product breakdown (Dependency-Track,
            # SonarQube) can filter the list; DefectDojo cannot, so send the
            # request where it is answerable instead of rendering an empty
            # table — this also catches bookmarks and the back button.
            if sev and not any(p.get("sev_known") for p in rows):
                to = (f"/security?platform={platform}&conn={sel['id']}"
                      f"&tab=findings&sev={sev}")
                if group:
                    to += f"&group={urllib.parse.quote(group)}"
                if q:
                    to += f"&q={urllib.parse.quote(q)}"
                return RedirectResponse(to, 303)
            if sev:
                rows = [p for p in rows if p["sev"].get(sev)]
            if q:
                rows = [p for p in rows if q.lower() in p["name"].lower()]
            block["products"] = rows
            block["total_products"] = n_products

    else:                                       # one product, exact severities
        block = {"conn": sel, "error": "",
                 "scope": names.get(sel.get("pid") or "", "All projects"),
                 "provider": security.PROVIDERS.get(sel.get("type"), {})}
        try:
            prod = security.product(sel, product)
            totals = prod["sev"]
            # Sonar's answer to "how is this project" is the quality gate and
            # the measures behind it, not a severity count — a project with no
            # vulnerabilities and a failing gate reads as clean otherwise
            if sel.get("type") == "sonarqube":
                sonar = security.sonar_detail(sel, product, fresh)
            if sev:
                # the tiles on this page carry &sev=, so honour it against this
                # product rather than rendering a filter that does nothing
                page = security.findings(sel, limit=security.page_size(sel),
                                         offset=max(0, offset), sev=sev,
                                         pid=product)
                prod = {**prod, "findings": page["rows"],
                        "findings_total": page["total"]}
        except Exception as e:                                # noqa: BLE001
            block["error"] = str(e)[:220]

    return templates.TemplateResponse(
        request, "security.html",
        ctx(request, level=level, cards=cards, block=block, prod=prod,
            sonar=sonar,
            conns=conns, present=present, providers=security.PROVIDERS,
            platform=platform, sel=sel, product=product, totals=totals,
            products=n_products,
            findings_n=(findings_head if findings_head is not None
                        else sum(totals.values())),
            tab=tab, sev=sev, q=q, group=group, offset=max(0, offset),
            fstatus=status if status in security.STATUSES else "",
            statuses_meta=security.STATUSES,
            msg=msg, err=err))


# ── security connection management (Settings) ──────────────────
def _sec_from_form(f) -> dict:
    return {"skip_tls": f.get("skip_tls") == "on",
            "type": str(f.get("type", "")).strip(),
            "name": str(f.get("name", "")).strip(),
            "base_url": str(f.get("base_url", "")).strip().rstrip("/"),
            "scope": str(f.get("scope", "")).strip(),
            "max_findings": str(f.get("max_findings", "")).strip()}


@app.post("/settings/sec/new")
async def sec_new(request: Request):
    f = await request.form()
    conn = _sec_from_form(f)
    conn["token"] = str(f.get("token", ""))
    pid = str(f.get("pid", ""))
    if conn["type"] not in security.PROVIDERS:
        return back(err="choose a security platform", to="/settings/security")
    prov = security.PROVIDERS[conn["type"]]
    if not conn["name"]:
        conn["name"] = prov["label"]
    missing = [k for k in prov["needs"] if not conn.get(k)]
    if missing:
        return back(err=f"missing for {prov['label']}: {', '.join(missing)}",
                    to="/settings/security")
    ok, detail = await run_in_threadpool(security.test, conn)
    conn["status"] = ("ok: " if ok else "failed: ") + detail
    store.add_sec(pid, conn)
    auth.audit(getattr(request.state, "user", None), "security_connected",
               f"{conn['type']}:{conn['name']}", detail, _client_ip(request))
    return (back(msg=f"{conn['name']} — {detail}", to="/settings/security")
            if ok else back(err=detail, to="/settings/security"))


@app.post("/settings/sec/{cid}/update")
async def sec_update(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    fields = _sec_from_form(f)
    fields.pop("type", None)
    if str(f.get("token", "")):
        fields["token"] = str(f.get("token"))
    store.update_sec(pid, cid, **fields)
    security.invalidate()
    ok, detail = await run_in_threadpool(security.test, store.get_sec(pid, cid) or {})
    store.update_sec(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/security") if ok
            else back(err=detail, to="/settings/security"))


@app.post("/settings/sec/{cid}/test")
async def sec_test(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    ok, detail = await run_in_threadpool(security.test, store.get_sec(pid, cid) or {})
    store.update_sec(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/security") if ok
            else back(err=detail, to="/settings/security"))


@app.post("/settings/sec/{cid}/delete")
async def sec_delete(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    name = (store.get_sec(pid, cid) or {}).get("name", cid)
    store.delete_sec(pid, cid)
    security.invalidate()
    auth.audit(getattr(request.state, "user", None), "security_removed", name,
               ip=_client_ip(request))
    return back(msg="connection removed", to="/settings/security")


# ── monitoring (display only — configuration lives in Settings) ──
@app.get("/monitoring", response_class=HTMLResponse)
def monitoring_page(request: Request, platform: str = "", conn: str = "",
                    sev: str = "", q: str = "", tab: str = "alerts",
                    sec: str = "", refresh: str = "", msg: str = "",
                    err: str = ""):
    """Alerts first, across every connected system.

    The reason this page exists rather than an embedded dashboard: a monitoring
    stack is normally per cluster, so no single Grafana can answer "what is
    firing everywhere". Collecting the alerts is the part only the portal can do.
    """
    from concurrent.futures import ThreadPoolExecutor
    conns = store.all_mon()
    names = {p_id: p["name"] for p_id, p in store.projects().items()}
    if refresh:
        monitoring.invalidate()
    sev = sev if sev in monitoring.SEVERITIES else ""

    present = [k for k in monitoring.PROVIDERS
               if any(c.get("type") == k for c in conns)]
    if platform and platform not in present:
        platform = ""
    sel = next((c for c in conns if c["id"] == conn), None) if conn else None
    if sel and platform and sel.get("type") != platform:
        sel = None

    need = ([sel] if sel else
            [c for c in conns if c.get("type") == platform] if platform else conns)

    def pull(c):
        try:
            return (c, monitoring.overview(c), "")
        except Exception as e:                                # noqa: BLE001
            return (c, None, str(e)[:200])

    got = []
    if need:
        with ThreadPoolExecutor(max_workers=min(5, len(need))) as pool:
            got = list(pool.map(pull, need))
    by_id = {c["id"]: (o, e) for c, o, e in got}
    totals = monitoring.merge_counts([o for _c, o, _e in got if o])

    # every alert from everything in scope, worst first — the whole point
    firing, broken = [], []
    for c, o, error in got:
        if error:
            broken.append({"conn": c, "error": error})
            continue
        for a in (o or {}).get("alerts", []):
            firing.append({**a, "conn": c["name"], "cid": c["id"],
                           "platform": c.get("type"),
                           "cluster": c.get("cluster") or "",
                           "scope": names.get(c.get("pid") or "", "All projects")})
    if sev:
        firing = [a for a in firing if a["severity"] == sev]
    if q:
        ql = q.lower()
        firing = [a for a in firing
                  if ql in a["name"].lower() or ql in (a["summary"] or "").lower()
                  or ql in (a["source"] or "").lower()]
    order = {s: i for i, s in enumerate(monitoring.SEVERITIES)}
    firing.sort(key=lambda a: (order.get(a["severity"], 9), a["name"].lower()))

    cards, block = [], None
    if sel:
        o, error = by_id.get(sel["id"], (None, ""))
        block = {"conn": sel, "over": o or {}, "error": error,
                 "scope": names.get(sel.get("pid") or "", "All projects"),
                 "provider": monitoring.PROVIDERS.get(sel.get("type"), {}),
                 "grafana": monitoring.deep_link(sel) if sel.get("type") == "grafana" else ""}
    elif platform:
        for c in need:
            o, error = by_id.get(c["id"], (None, ""))
            cards.append({"conn": c, "over": o or {}, "error": error,
                          "provider": monitoring.PROVIDERS.get(platform, {}),
                          "scope": names.get(c.get("pid") or "", "All projects"),
                          "href": f"/monitoring?platform={platform}&conn={c['id']}"})
    else:
        for key in present:
            mine = [c for c in conns if c.get("type") == key]
            obs = [by_id.get(c["id"], (None, ""))[0] for c in mine]
            cards.append({
                "key": key, "provider": monitoring.PROVIDERS[key], "conns": mine,
                "counts": monitoring.merge_counts([o for o in obs if o]),
                "items": sum((o or {}).get("items", 0) for o in obs),
                "unit": next(((o or {}).get("unit") for o in obs if o), "item"),
                "broken": sum(1 for c in mine if by_id.get(c["id"], (None, ""))[1]),
                "href": f"/monitoring?platform={key}"})

    # Everything below is a projection of what was already collected. The page
    # used to render the alert list and throw the rest away — including every
    # dashboard, which `overview()` has always fetched.
    dashboards, dash_seen = [], set()
    for c, o, error in got:
        for d in (o or {}).get("dashboards", []):
            if (key := (c["id"], d["url"])) in dash_seen:
                continue
            dash_seen.add(key)
            dashboards.append({**d, "conn": c["name"], "cid": c["id"],
                               "platform": c.get("type")})

    def _tally(rows, field):
        """Counts by one field, biggest first, blanks folded into one bucket."""
        seen: dict[str, int] = {}
        for r in rows:
            seen[(r.get(field) or "").strip() or "—"] = \
                seen.get((r.get(field) or "").strip() or "—", 0) + 1
        return sorted(({"label": k, "n": v} for k, v in seen.items()),
                      key=lambda x: (-x["n"], x["label"].lower()))

    # The tallies are built from `firing` AFTER filtering, so a bar and the list
    # it links to are the same rows — the clickable-tiles rule reaches here.
    by_source = _tally(firing, "source")
    by_system = _tally(firing, "conn")
    by_scope = _tally(firing, "scope")
    folders = _tally(dashboards, "folder")
    suppressed = sum(1 for a in firing if a.get("state") not in ("active", ""))
    tags: dict[str, int] = {}
    for d in dashboards:
        for t in d.get("tags") or []:
            tags[t] = tags.get(t, 0) + 1

    cur = sec if sec in ("overview", "firing", "dashboards", "systems") else "overview"
    sections = [
        {"key": "overview", "label": "Overview", "icon": "activity"},
        {"key": "firing", "label": "Firing", "icon": "bell",
         "count": len(firing)},
        {"key": "dashboards", "label": "Dashboards", "icon": "chart-line",
         "count": len(dashboards)},
        {"key": "systems", "label": "Systems", "icon": "boxes",
         "count": len(conns)},
    ]

    return templates.TemplateResponse(
        request, "monitoring.html",
        ctx(request, cards=cards, block=block, conns=conns, present=present,
            providers=monitoring.PROVIDERS, platform=platform, sel=sel,
            firing=firing, totals=totals, broken=broken, sev=sev, q=q, tab=tab,
            stage=("detail" if sel else "provider" if platform else "hub"),
            play_speeds=PLAY_SPEEDS,
            dashboards=dashboards, by_source=by_source, by_system=by_system,
            by_scope=by_scope, folders=folders, dash_tags=[{"label": k, "value": v}
                       for k, v in sorted(tags.items(), key=lambda kv: (-kv[1], kv[0]))],
            suppressed=suppressed, sections=sections, sec=cur,
            msg=msg, err=err))


def _gdash_open(request: Request, conn: str, uid: str, refresh: bool):
    """The connection, dashboard, time range and resolved variables for one view.

    Shared by the page and by every panel fragment, so the two can never
    disagree about which host `$node` means. The variable lookups and the
    definition are cached, so a dashboard of twenty panels resolves them once.
    """
    sel = next((c for c in store.all_mon() if c["id"] == conn), None)
    if not sel:
        raise HTTPException(404, "that system is not connected")
    dash = grafana.dashboard(sel, uid, refresh=refresh)
    q = request.query_params
    trange = grafana.time_range(q.get("from") or dash["time"].get("from") or "now-6h",
                                q.get("to") or dash["time"].get("to") or "now")
    chosen: dict[str, list[str]] = {}
    for k, v in q.multi_items():
        if k.startswith("var-"):
            chosen.setdefault(k[4:], []).append(v)
    vars_ = grafana.variables(sel, dash, chosen, trange, refresh=refresh)
    return sel, dash, trange, vars_


def _gdash_query(sel, dash, trange, vars_) -> str:
    """The view as query parameters -- the RESOLVED variables, not the raw ask."""
    parts = [("conn", sel["id"]), ("uid", dash["uid"]),
             ("from", trange["from"]), ("to", trange["to"])]
    for v in vars_:
        for val in v["current"]:
            parts.append((f"var-{v['name']}", val))
    return urllib.parse.urlencode(parts)


def _all_dashboards() -> list:
    """Every Grafana dashboard the portal can draw, across every connection,
    in the order the Dashboards tab lists them. Cached per connection."""
    out = []
    for c in store.all_mon():
        if c.get("type") != "grafana":
            continue
        try:
            for d in monitoring.dashboards(c):
                out.append({**d, "cid": c["id"], "conn": c["name"], "platform": "grafana"})
        except Exception:                                        # noqa: BLE001
            continue
    return out


PLAY_HOLD = 5            # seconds at the bottom before moving on, by default


def _play_url(d: dict, plist: str, index: int, every: int, kiosk: bool,
              scroll: bool = True, hold: int = PLAY_HOLD, speed="auto") -> str:
    q = {"conn": d["cid"], "uid": d["uid"], "plist": plist, "pi": index, "every": every}
    if kiosk:
        q["kiosk"] = 1
    # scrolling is the default, so only its absence is spelled out -- a
    # bookmark made before it existed scrolls too, which is what was asked for
    if not scroll:
        q["scroll"] = 0
    if hold != PLAY_HOLD:
        q["hold"] = hold
    if speed != "auto":
        q["speed"] = speed
    return "/monitoring/dashboard?" + urllib.parse.urlencode(q)


# Scroll speed in pixels per second, or "auto" -- paced to fit the time on each
# dashboard. A fixed speed is the operator's call and is honoured between a
# crawl and a blur; auto keeps its own narrower, readable band in the browser.
PLAY_SPEEDS = (("auto", "auto"), ("25", "slow"), ("60", "medium"),
               ("120", "fast"), ("250", "very fast"))


def _play_speed(speed):
    if str(speed).strip().lower() in ("", "auto"):
        return "auto"
    try:
        return max(10, min(600, int(speed)))
    except (TypeError, ValueError):
        return "auto"


def _play_scroll(scroll) -> bool:
    return str(scroll).lower() not in ("0", "off", "false", "no")


def _play_hold(hold) -> int:
    try:
        return max(0, min(120, int(hold)))
    except (TypeError, ValueError):
        return PLAY_HOLD


def _play_every(every) -> int:
    try:
        return max(10, min(3600, int(every)))
    except (TypeError, ValueError):
        return 60


@app.get("/monitoring/play")
def monitoring_play(plist: str = "all", every: str = "60", kiosk: str = "",
                    scroll: str = "1", hold: str = str(PLAY_HOLD), speed: str = "auto"):
    """Start a playlist: the first dashboard it selects, with the rotation on."""
    items = grafana.playlist(_all_dashboards(), plist)
    if not items:
        return RedirectResponse("/monitoring?sec=dashboards&err=" + urllib.parse.quote(
            f"no dashboard matches “{grafana.playlist_label(plist)}”"), 303)
    return RedirectResponse(_play_url(items[0], plist, 0, _play_every(every),
                                      kiosk in ("1", "on", "true"),
                                      _play_scroll(scroll), _play_hold(hold),
                                      _play_speed(speed)), 303)


@app.get("/monitoring/dashboard", response_class=HTMLResponse)
def monitoring_dashboard(request: Request, conn: str = "", uid: str = "",
                         refresh: str = "", refresh_every: str = "", err: str = "",
                         plist: str = "", pi: int = 0, every: str = "60",
                         kiosk: str = "", scroll: str = "1",
                         hold: str = str(PLAY_HOLD), speed: str = "auto"):
    """One Grafana dashboard, drawn the way Grafana draws it.

    The page is the layout, the variable bar and the time range; every panel's
    body is fetched separately (`/monitoring/dashboard/panel`), a few at a time,
    because a dashboard is a dozen queries or a hundred and waiting for the
    slowest before drawing any of them is exactly what this product refuses
    elsewhere. Panels inside a closed row are not queried until it is opened.
    """
    try:
        sel, dash, trange, vars_ = _gdash_open(request, conn, uid, bool(refresh))
    except HTTPException:
        return RedirectResponse("/monitoring?sec=dashboards&err=" +
                                urllib.parse.quote("that system is not connected"), 303)
    except Exception as e:                                       # noqa: BLE001
        return RedirectResponse(
            "/monitoring?sec=dashboards&err=" + urllib.parse.quote(str(e)[:200]), 303)
    scope = grafana.scope_of(vars_)
    for p in dash["panels"]:
        p["title_shown"] = grafana.interpolate(p["title"], scope, {}, "raw")
    secs = grafview.sections(dash["panels"])
    for sec in secs:
        if sec["row"]:
            sec["row"]["title_shown"] = grafana.interpolate(sec["row"]["title"], scope, {}, "raw")
    viewq = _gdash_query(sel, dash, trange, vars_)
    tv = kiosk in ("1", "on", "true")
    play = None
    if plist:
        items = grafana.playlist(_all_dashboards(), plist)
        if items:
            n = len(items)
            here = items[pi] if 0 <= pi < n else None
            # The list is recomputed on every step, so a dashboard added or
            # removed while the screen runs is picked up -- and the position is
            # re-found by identity when the index no longer points here.
            if not here or (here["uid"], here["cid"]) != (uid, conn):
                pi = next((i for i, d in enumerate(items)
                           if (d["uid"], d["cid"]) == (uid, conn)), 0)
            sec_every = _play_every(every)
            sc, hd, sp = _play_scroll(scroll), _play_hold(hold), _play_speed(speed)
            nxt, prv = (pi + 1) % n, (pi - 1) % n
            play = {"spec": plist, "label": grafana.playlist_label(plist),
                    "index": pi, "total": n, "every": sec_every,
                    "scroll": sc, "hold": hd, "speed": sp,
                    "next": _play_url(items[nxt], plist, nxt, sec_every, tv, sc, hd, sp),
                    "prev": _play_url(items[prv], plist, prv, sec_every, tv, sc, hd, sp),
                    "next_title": items[nxt]["title"],
                    "stop": f"/monitoring/dashboard?conn={urllib.parse.quote(conn)}"
                            f"&uid={urllib.parse.quote(uid)}",
                    "tv_on": _play_url(items[pi], plist, pi, sec_every, True, sc, hd, sp),
                    "tv_off": _play_url(items[pi], plist, pi, sec_every, False, sc, hd, sp)}
    auto = 0
    if refresh_every.isdigit():
        auto = int(refresh_every)
    elif dash.get("refresh") and not refresh_every:
        auto = grafana._prom_to_ms(str(dash["refresh"])) // 1000
    return templates.TemplateResponse(
        request, "monitoring_dashboard.html",
        ctx(request, dash=dash, sel=sel, vars=vars_, trange=trange,
            sections=secs, quick=grafana.QUICK_RANGES,
            quick_hit=any(k == trange["from"] for k, _ in grafana.QUICK_RANGES)
            and trange["to"] == "now",
            panel_total=sum(1 for p in dash["panels"] if not p["is_row"]),
            collapsed=sum(1 for p in dash["panels"] if p["hidden"]),
            self_url="/monitoring/dashboard?" + viewq,
            panel_base="/monitoring/dashboard/panel?" + viewq +
            ("&refresh=1" if refresh else ""),
            # a playlist reloads the page on every step, so a refresh timer on
            # top of it would only fetch everything twice
            auto=0 if play else (auto if auto >= 10 else 0),
            play=play, tv=tv,
            tv_off_url="/monitoring/dashboard?" + viewq, tv_on_url="/monitoring/dashboard?" + viewq + "&kiosk=1",
            err=err))


@app.get("/monitoring/dashboard/panel", response_class=HTMLResponse)
def monitoring_dashboard_panel(request: Request, conn: str = "", uid: str = "",
                               panel: int = 0, w: int = 800, refresh: str = ""):
    """One panel's body, rendered. Fetched by the dashboard page, never linked."""
    try:
        sel, dash, trange, vars_ = _gdash_open(request, conn, uid, False)
    except Exception as e:                                       # noqa: BLE001
        return HTMLResponse(f'<div class="gp-empty bad">{grafview.esc(str(e)[:200])}</div>')
    p = next((x for x in dash["panels"] if x["id"] == panel and not x["is_row"]), None)
    if not p:
        return HTMLResponse('<div class="gp-empty">this panel is no longer on the dashboard</div>')
    scope = grafana.scope_of(vars_)
    data = {"frames": [], "errors": []}
    if p["type"] in grafview.DRAWN and p["type"] != "text":
        try:
            data = grafana.run_panel(sel, dash, p, scope, trange,
                                     width_px=max(200, min(3000, int(w or 800))),
                                     refresh=bool(refresh))
        except Exception as e:                                   # noqa: BLE001
            data = {"frames": [], "errors": [str(e)[:200]]}
    body = grafview.render(p, data, trange, _mdlite,
                           grafana_url=f"{dash['url']}?viewPanel={p['id']}")
    return HTMLResponse(str(body))


# ── monitoring connection management (Settings) ────────────────
def _mon_from_form(f) -> dict:
    return {"skip_tls": f.get("skip_tls") == "on",
            "type": str(f.get("type", "")).strip(),
            "name": str(f.get("name", "")).strip(),
            "base_url": str(f.get("base_url", "")).strip().rstrip("/"),
            "cluster": str(f.get("cluster", "")).strip(),
            "username": str(f.get("username", "")).strip()}


@app.get("/settings/clouds", response_class=HTMLResponse)
def settings_clouds(request: Request, msg: str = "", err: str = ""):
    return templates.TemplateResponse(
        request, "set_clouds.html",
        ctx(request, cloud_conns=store.all_cloud(), providers=cloud.PROVIDERS,
            cloud_fields={k: v["fields"] for k, v in cloud.PROVIDERS.items()},
            cloud_notes={k: v["note"] for k, v in cloud.PROVIDERS.items()},
            project_names={k: v["name"] for k, v in store.projects().items()},
            msg=msg, err=err))


def _cloud_from_form(f) -> dict:
    return {"type": str(f.get("type", "")).strip(),
            "name": str(f.get("name", "")).strip(),
            "tenant": str(f.get("tenant", "")).strip(),
            "base_url": str(f.get("base_url", "")).strip().rstrip("/"),
            "key_id": str(f.get("key_id", "")).strip(),
            "region": str(f.get("region", "")).strip()}


@app.post("/settings/cloud/new")
async def cloud_new(request: Request):
    f = await request.form()
    conn = _cloud_from_form(f)
    conn["secret"] = str(f.get("secret", ""))
    pid = str(f.get("pid", ""))
    if conn["type"] not in cloud.PROVIDERS:
        return back(err="choose a provider", to="/settings/clouds")
    if not conn["name"]:
        conn["name"] = cloud.PROVIDERS[conn["type"]]["label"]
    ok, detail = await run_in_threadpool(cloud.test, conn)
    conn["status"] = ("ok: " if ok else "failed: ") + detail
    store.add_cloud(pid, conn)
    auth.audit(getattr(request.state, "user", None), "cloud_connected",
               f"{conn['type']}:{conn['name']}", detail, _client_ip(request))
    return (back(msg=f"{conn['name']} — {detail}", to="/settings/clouds")
            if ok else back(err=f"added, but verification failed: {detail}",
                            to="/settings/clouds"))


@app.post("/settings/cloud/{cid}/update")
async def cloud_update(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    fields = _cloud_from_form(f)
    fields.pop("type", None)
    if str(f.get("secret", "")).strip():
        fields["secret"] = str(f.get("secret"))
    store.update_cloud(pid, cid, **fields)
    ok, detail = await run_in_threadpool(cloud.test, store.get_cloud(pid, cid) or {})
    store.update_cloud(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/clouds") if ok
            else back(err=detail, to="/settings/clouds"))


@app.post("/settings/cloud/{cid}/test")
async def cloud_test(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    ok, detail = await run_in_threadpool(cloud.test, store.get_cloud(pid, cid) or {})
    store.update_cloud(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/clouds") if ok
            else back(err=detail, to="/settings/clouds"))


@app.post("/settings/cloud/{cid}/delete")
async def cloud_delete(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    conn = store.get_cloud(pid, cid) or {}
    store.delete_cloud(pid, cid)
    auth.audit(getattr(request.state, "user", None), "cloud_removed",
               conn.get("name", cid), ip=_client_ip(request))
    return back(msg="account removed", to="/settings/clouds")


@app.get("/settings/storage", response_class=HTMLResponse)
def settings_storage(request: Request, msg: str = "", err: str = ""):
    return templates.TemplateResponse(
        request, "set_storage.html",
        ctx(request, stor_conns=store.all_stor(), providers=stordev.PROVIDERS,
            stor_notes={k: v["note"] for k, v in stordev.PROVIDERS.items()},
            stor_hints={k: v["url_hint"] for k, v in stordev.PROVIDERS.items()},
            project_names={k: v["name"] for k, v in store.projects().items()},
            msg=msg, err=err))


def _stor_from_form(f) -> dict:
    return {"type": str(f.get("type", "")).strip(),
            "name": str(f.get("name", "")).strip(),
            "base_url": str(f.get("base_url", "")).strip().rstrip("/"),
            "purpose": str(f.get("purpose", "")).strip(),
            "username": str(f.get("username", "")).strip(),
            "skip_tls": "1" if f.get("skip_tls") else ""}


@app.post("/settings/stor/new")
async def stor_new(request: Request):
    f = await request.form()
    conn = _stor_from_form(f)
    conn["token"] = str(f.get("token", ""))
    pid = str(f.get("pid", ""))
    if conn["type"] not in stordev.PROVIDERS:
        return back(err="choose a device type", to="/settings/storage")
    prov = stordev.PROVIDERS[conn["type"]]
    if not conn["name"]:
        conn["name"] = prov["label"]
    if not conn["base_url"]:
        return back(err=f"{prov['label']} needs an address", to="/settings/storage")
    ok, detail = await run_in_threadpool(stordev.test, conn)
    conn["status"] = ("ok: " if ok else "failed: ") + detail
    store.add_stor(pid, conn)
    auth.audit(getattr(request.state, "user", None), "storage_device_added",
               f"{conn['type']}:{conn['name']}", detail, _client_ip(request))
    return (back(msg=f"{conn['name']} — {detail}", to="/settings/storage")
            if ok else back(err=f"added, but the check failed: {detail}",
                            to="/settings/storage"))


@app.post("/settings/stor/{cid}/update")
async def stor_update(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    fields = _stor_from_form(f)
    fields.pop("type", None)
    if str(f.get("token", "")):
        fields["token"] = str(f.get("token"))
    store.update_stor(pid, cid, **fields)
    ok, detail = await run_in_threadpool(stordev.test, store.get_stor(pid, cid) or {})
    store.update_stor(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/storage") if ok
            else back(err=detail, to="/settings/storage"))


@app.post("/settings/stor/{cid}/test")
async def stor_test(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    ok, detail = await run_in_threadpool(stordev.test, store.get_stor(pid, cid) or {})
    store.update_stor(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/storage") if ok
            else back(err=detail, to="/settings/storage"))


@app.post("/settings/stor/{cid}/delete")
async def stor_delete(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    conn = store.get_stor(pid, cid) or {}
    store.delete_stor(pid, cid)
    auth.audit(getattr(request.state, "user", None), "storage_device_removed",
               conn.get("name", cid), ip=_client_ip(request))
    return back(msg="device removed", to="/settings/storage")


@app.post("/settings/mon/new")
async def mon_new(request: Request):
    f = await request.form()
    conn = _mon_from_form(f)
    conn["token"] = str(f.get("token", ""))
    pid = str(f.get("pid", ""))
    if conn["type"] not in monitoring.PROVIDERS:
        return back(err="choose a monitoring system", to="/settings/monitoring")
    prov = monitoring.PROVIDERS[conn["type"]]
    if not conn["name"]:
        conn["name"] = prov["label"]
    missing = [k for k in prov["needs"] if not conn.get(k)]
    if missing:
        return back(err=f"missing for {prov['label']}: {', '.join(missing)}",
                    to="/settings/monitoring")
    ok, detail = await run_in_threadpool(monitoring.test, conn)
    conn["status"] = ("ok: " if ok else "failed: ") + detail
    store.add_mon(pid, conn)
    auth.audit(getattr(request.state, "user", None), "monitoring_connected",
               f"{conn['type']}:{conn['name']}", detail, _client_ip(request))
    return (back(msg=f"{conn['name']} — {detail}", to="/settings/monitoring")
            if ok else back(err=detail, to="/settings/monitoring"))


@app.post("/settings/mon/{cid}/update")
async def mon_update(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    fields = _mon_from_form(f)
    fields.pop("type", None)
    if str(f.get("token", "")):
        fields["token"] = str(f.get("token"))
    store.update_mon(pid, cid, **fields)
    monitoring.invalidate()
    ok, detail = await run_in_threadpool(monitoring.test, store.get_mon(pid, cid) or {})
    store.update_mon(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/monitoring") if ok
            else back(err=detail, to="/settings/monitoring"))


@app.post("/settings/mon/{cid}/test")
async def mon_test(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    ok, detail = await run_in_threadpool(monitoring.test, store.get_mon(pid, cid) or {})
    store.update_mon(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/monitoring") if ok
            else back(err=detail, to="/settings/monitoring"))


@app.post("/settings/mon/{cid}/delete")
async def mon_delete(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    name = (store.get_mon(pid, cid) or {}).get("name", cid)
    store.delete_mon(pid, cid)
    monitoring.invalidate()
    auth.audit(getattr(request.state, "user", None), "monitoring_removed", name,
               ip=_client_ip(request))
    return back(msg="connection removed", to="/settings/monitoring")



# ── server & asset inventory ───────────────────────────────────
# ── IT spend: what we pay for ────────────────────────────────────────
@app.get("/spend", response_class=HTMLResponse)
def spend_year(request: Request, year_q: str = Query("", alias="year"),
               show_in: str = Query("", alias="in"),
               msg: str = "", err: str = ""):
    """The year, month by month, and nothing else.

    Everything else this page used to carry — the register, the rates, the
    cloud accounts, a month's lines and two breakdown charts — is a different
    question from the one people open it with, which is "what did each month
    cost". A month opens its own page now; the machinery lives at
    /spend/manage.
    """
    if show_in:
        spend.set_display_currency(show_in)
    _spend_sync_clouds()
    # `year=all` zooms out one level: a box per year rather than per month.
    # Same component, same split, so nothing new has to be learned to read it.
    if str(year_q).strip().lower() == "all":
        return templates.TemplateResponse(
            request, "spend_years.html",
            ctx(request, av=spend.years_view(), msg=msg, err=err,
                **_spend_form()))
    try:
        year = int(year_q or 0)
    except ValueError:
        year = 0
    yv = spend.year_view(year)
    return templates.TemplateResponse(
        request, "spend.html",
        ctx(request, yv=yv, msg=msg, err=err, **_spend_form()))


def _spend_form() -> dict:
    """What the add/edit dialog needs, wherever it is included.

    The dialog is on three pages; a page that forgot one of these rendered a
    500 rather than a missing dropdown, so they are handed over as one thing.
    """
    return {"categories": spend.CATEGORIES, "kinds": spend.KINDS,
            "cycles": spend.CYCLES, "statuses": spend.STATUSES,
            "vendors": spend.distinct("vendor"), "t": spend.totals(),
            "choices": spend.currencies_in_use()}


def _spend_sync_clouds() -> None:
    """A connected cloud account's bill changes every month, so it is read
    rather than typed. Kicked off behind the page: the bills reader is cached,
    so this is free when warm and must not make the page wait when it is not."""
    age = spend.cloud_sync_age()
    if store.all_cloud() and (age is None or age > 6):
        threading.Thread(target=spend.sync_clouds,
                         kwargs={"actor": "automatic"},
                         name="spend-cloud-sync", daemon=True).start()


@app.get("/spend/manage", response_class=HTMLResponse)
def subs_page(request: Request, q: str = "", category: str = "",
              vendor: str = "", status: str = "active", sort: str = "renews",
              month: str = "", show_in: str = Query("", alias="in"),
              tab: str = "", year: int = 0, m: str = "",
              msg: str = "", err: str = ""):
    # ?in=AED switches the currency everything is shown in, and sticks — the
    # question is usually asked in one currency for weeks at a time
    if show_in:
        spend.set_display_currency(show_in)
    _spend_sync_clouds()
    rows = spend.search(q=q, category=category, vendor=vendor, status=status,
                        sort=sort)
    filtered = bool(q or category or vendor or month or status != "active")
    # clicking a month on either chart narrows the register to what that month
    # is made of — the charts were previously a picture with no way in
    fcast = spend.forecast(12)
    picked = next((m for m in fcast["months"] if m["ym"] == month), None)
    if month:
        wanted = {r["name"] for r in (picked or {}).get("rows", [])}
        rows = [r for r in rows if r["name"] in wanted]
    # totals cover every active row, not the filtered view: a monthly run rate
    # that changes when you search would be worse than useless
    # the year grid, and whichever box is open under it. Defaults to the month
    # just gone: "what did we spend last month" is the question this page is
    # opened for, and a page that opens on nothing makes everybody click once
    # before it says anything.
    yv = spend.year_view(year)
    if m == "all":
        det, pick = spend.year_lines(yv["year"]), "all"
    else:
        today = dt.date.today()
        default = (today.month - 1) or 12
        if yv["year"] != today.year:
            default = 12
        try:
            n = min(12, max(1, int(m))) if m else default
        except ValueError:
            n = default
        det, pick = spend.month_detail(f"{yv['year']:04d}-{n:02d}"), str(n)
    groups = spend.cycle_groups(rows)
    known = {g["key"] for g in groups if g["always"] or g["rows"]}
    tab = tab if tab in known else "all"
    return templates.TemplateResponse(
        request, "spend_manage.html",
        ctx(request, rows=rows, t=spend.totals(), q=q, category=category,
            status_filter=status, sort=sort, categories=spend.CATEGORIES,
            kinds=spend.KINDS, cycles=spend.CYCLES, statuses=spend.STATUSES,
            soon_days=spend.SOON_DAYS, vendors=spend.distinct("vendor"),
            fc=fcast,
            month=month, picked=picked,
            # the register is a table per billing cycle; the tabs are rendered
            # together so switching costs nothing, and the chosen one rides in
            # the URL so a filter or an add comes back where you were
            groups=groups, tab=tab, filtered=filtered,
            yv=yv, det=det, pick=pick, buckets=spend.BUCKETS,
            clouds=store.all_cloud(), synced=spend.cloud_synced_at(),
            sync_age=spend.cloud_sync_age(),
            # keyed by source so the card can show a linked account's figure
            # whether or not the current filter includes its row
            rows_by_source={r["source"]: r for r in spend.search(status="")
                            if r.get("source")},
            fx=spend.rate_rows(), pivot=spend.PIVOT,
            choices=spend.currencies_in_use(), stale_days=spend.STALE_DAYS,
            qs=str(request.url.query or ""), msg=msg, err=err))


# Only paths inside the portal, and only the spend pages: `back` arrives in a
# form post, and a redirect that will follow anything it is handed is an open
# redirect however friendly the intent.
_SPEND_PAGES = ("/spend", "/spend/month", "/spend/manage")


def _spend_back(tab: str, back: str = "", **flash) -> str:
    """Where the save should land: where the editor was opened from.

    The dialog is on three pages now — the calendar, a month, the register —
    and sending every save to the register meant an expense added from the
    calendar dumped you on a page you had not asked for and did not want.
    """
    path, _, query = (back or "").partition("?")
    if path in _SPEND_PAGES:
        return _with(path, query, **flash)
    url = _with("/spend/manage", f"tab={urllib.parse.quote(tab)}" if tab else "", **flash)
    return url + "#register"


@app.post("/spend/save")
async def subs_save(request: Request):
    f = dict(await request.form())
    rid = str(f.get("id", "")).strip()
    tab = str(f.pop("tab", "")).strip()
    back = str(f.pop("back", "")).strip()
    who = (getattr(request.state, "user", None) or {}).get("email", "")
    try:
        if rid:
            spend.update(rid, f, who)
            what, name = "updated", f.get("name", "")
        else:
            rid = spend.create(f, who)
            what, name = "added", f.get("name", "")
    except ValueError as exc:
        return RedirectResponse(_spend_back(tab, back, err=str(exc)), 303)
    auth.audit(getattr(request.state, "user", None), "subscription", what,
               f"{name} · {f.get('vendor', '')}", _client_ip(request))
    return RedirectResponse(_spend_back(tab, back, msg=f"{name} {what}."), 303)


@app.post("/spend/delete")
async def subs_delete(request: Request):
    f = await request.form()
    rid = str(f.get("id", "")).strip()
    back = str(f.get("back", "")).strip()
    if str(f.get("confirm", "")).strip().casefold() != "delete":
        return RedirectResponse(
            _spend_back("", back, err="Type Delete to remove a record."), 303)
    row = spend.get(rid)
    if not row:
        return RedirectResponse(
            _spend_back("", back, err="That record no longer exists."), 303)
    spend.delete(rid)
    auth.audit(getattr(request.state, "user", None), "subscription", "deleted",
               row["name"], _client_ip(request))
    return RedirectResponse(
        _spend_back("", back, msg=f"{row['name']} removed from the register."), 303)


@app.post("/spend/sync")
async def spend_sync(request: Request):
    """Read every connected cloud account's bill into the register, now."""
    rep = spend.sync_clouds(refresh=True, actor="manual sync")
    bits = []
    if rep["updated"]:
        bits.append(", ".join(
            f"{u['name']} → {spend.money(u['cost'], u['currency'])}"
            f" ({u['month']})" for u in rep["updated"][:4]))
    if rep["unchanged"]:
        bits.append(f"{len(rep['unchanged'])} unchanged")
    if not rep["accounts"]:
        bits.append("no cloud accounts are connected")
    auth.audit(getattr(request.state, "user", None), "subscription",
               "cloud sync",
               f"{len(rep['updated'])} updated, {len(rep['failed'])} failed",
               _client_ip(request))
    q = {}
    if rep["failed"]:
        # named, and explicit that the old figure was kept: a failed read that
        # looks like a successful zero is the worst outcome here
        q["err"] = "Could not read " + "; ".join(
            f"{f['name']} ({f['why']})"
            + (" — the last known figure was kept" if f["kept"] else "")
            for f in rep["failed"][:3])
    if bits:
        q["msg"] = "Read from the cloud accounts: " + " · ".join(bits) + "."
    return RedirectResponse(_with("/spend", "", **q), 303)


@app.post("/spend/currency")
async def subs_currency(request: Request):
    f = await request.form()
    shown = str(f.get("display", "")).strip()
    code = str(f.get("code", "")).strip()
    rate = str(f.get("rate", "")).strip()
    told = []
    if shown:
        spend.set_display_currency(shown)
        told.append(f"showing {spend.display_currency()}")
    if code and rate:
        if not spend.set_rate(code, rate):
            return RedirectResponse(_with(
                "/spend", "", err=f"{code or 'that'} is not a currency code and "
                                  f"a rate of {rate or 'nothing'}, so nothing "
                                  f"was saved."), 303)
        told.append(f"1 {spend.PIVOT} = {rate} {code.upper()}")
    elif code or rate:
        return RedirectResponse(_with(
            "/spend", "", err="A rate needs both a currency and a number."), 303)
    if not told:
        return RedirectResponse(_with("/spend", "", err="Nothing to save."), 303)
    auth.audit(getattr(request.state, "user", None), "subscription",
               "currency", " · ".join(told), _client_ip(request))
    return RedirectResponse(_with("/spend", "", msg=" · ".join(told) + "."), 303)


@app.get("/spend/month", response_class=HTMLResponse)
def subs_month(request: Request, ym: str = ""):
    """Everything charged in one month, line by line, with a total.

    Its own page rather than a section: "what did we spend last month" is a
    question people arrive with, and it should be one link away and printable,
    not something to scroll past two charts to reach.
    """
    got = spend.month_detail(ym)
    return templates.TemplateResponse(
        request, "spend_month.html", ctx(request, d=got, **_spend_form()))


@app.get("/spend/export.csv")
def subs_csv(request: Request, q: str = "", category: str = "",
                 vendor: str = "", status: str = "active",
                 sort: str = "renews", month: str = ""):
    rows = spend.search(q=q, category=category, vendor=vendor, status=status,
                        sort=sort)
    # clicking a month on either chart narrows the register to what that month
    # is made of — the charts were previously a picture with no way in
    fcast = spend.forecast(12)
    picked = next((m for m in fcast["months"] if m["ym"] == month), None)
    if month:
        wanted = {r["name"] for r in (picked or {}).get("rows", [])}
        rows = [r for r in rows if r["name"] in wanted]
    base = spend.base_currency()
    header = ["name", "vendor", "category", "kind", "seats", "cost", "currency",
              "cycle", f"per month ({base})", f"per year ({base})", "converted",
              "started", "renews", "auto_renew", "status", "owner", "account",
              "url", "notes"]
    body = [[r["name"], r["vendor"], r["category_label"], r["kind"], r["seats"],
             f"{r['cost']:.2f}", r["currency"], r["cycle"],
             f"{r['base_monthly']:.2f}", f"{r['base_yearly']:.2f}",
             "yes" if r["converted"] else "no",
             r["started"], r["renews"], "yes" if r["auto_renew"] else "no",
             r["status"], r["owner"], r["account"], r["url"],
             (r["notes"] or "").replace("\n", " ")]
            for r in rows]
    auth.audit(getattr(request.state, "user", None), "subscription",
               "exported", f"{len(rows)} rows", _client_ip(request))
    return Response(audit.as_csv(header, body), media_type="text/csv",
                    headers={"Content-Disposition":
                             'attachment; filename="it-spend.csv"'})


@app.get("/assets", response_class=HTMLResponse)
def assets_page(request: Request, q: str = "", sort: str = "hostname",
                desc: str = "", page: int = 1, msg: str = "", err: str = ""):
    """Inventory list. Filters arrive as plain column names in the query string,
    so a saved link like ?placement=on-prem&env=prod keeps working as columns
    are added. They are read from the raw query string rather than declared as
    parameters, because which ones exist depends on the columns."""
    # `class` is not a column: it is the physical/virtual split, applied by the
    # same clause the tiles link to
    known = {n for n, _t in assets.COLUMNS} | {"class"}
    active = {k: v for k, v in request.query_params.items()
              if k in known and (v in assets.CLASSES if k == "class" else v)}
    per = 100
    page = max(1, int(page or 1))
    res = assets.search(q=q, filters=active, sort=sort, desc=bool(desc),
                        limit=per, offset=(page - 1) * per)
    names = {k: v["name"] for k, v in store.projects().items()}
    # each filter offers the values the inventory actually holds, so the list
    # grows with the data; a project id is shown by its name
    facets = []
    for col in assets.FACETS:
        vals = assets.distinct(col)
        if vals:
            facets.append({
                "col": col,
                "label": "project" if col == "pid" else col,
                "options": [(v, names.get(v, v) if col == "pid" else v)
                            for v in vals],
            })
    return templates.TemplateResponse(
        request, "assets.html",
        ctx(request, res=res, q=q, sort=sort, desc=bool(desc), page=page,
            per=per, active=active,
            stats=assets.stats(q=q, filters=active),
            suggest=assets.suggestions(), facets=facets,
            project_names=names, msg=msg, err=err))


@app.get("/assets/new", response_class=HTMLResponse)
def asset_new_form(request: Request, err: str = ""):
    return templates.TemplateResponse(
        request, "asset_form.html",
        ctx(request, asset=None, suggest=assets.suggestions(),
            attr_keys=assets.attribute_keys(), columns=assets.COLUMNS,
            project_names={k: v["name"] for k, v in store.projects().items()},
            err=err))


# literal paths must precede the {aid} catch-all
@app.api_route("/assets/export.csv", methods=["GET", "POST"])
async def asset_export(request: Request):
    """Export what is on screen: the current filters, or a selection.

    GET carries the filters in the query string, exactly as the list page does.
    POST carries ticked ids from the table form — a selection can be longer than
    a URL should be.
    """
    import io
    known = {n for n, _t in assets.COLUMNS}
    ids, source = [], request.query_params
    if request.method == "POST":
        form = await request.form()
        ids = [v for v in form.getlist("ids") if v]
        # the filters that were in force travel with the form, so a selection
        # export and a filtered export come out sorted the same way
        source = dict(urllib.parse.parse_qsl(
            (form.get("back") or "").partition("?")[2]))
    q = source.get("q", "")
    sort = source.get("sort", "hostname")
    desc = bool(source.get("desc", ""))
    filters = {k: v for k, v in source.items()
               if (k in known and v) or (k == "class" and v in assets.CLASSES)}
    header, rows = assets.export_rows(q=q, filters=filters, ids=ids,
                                      sort=sort, desc=desc)
    buf = io.StringIO()
    w = csvsafe.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    # the filename says what the file holds, so three exports in a downloads
    # folder are still tellable apart
    if ids:
        name = f"assets-selection-{len(rows)}"
    elif filters or q:
        bits = [f"{k}-{v}" for k, v in sorted(filters.items()) if k != "pid"]
        name = "assets-" + ("-".join(bits) or "filtered")
    else:
        name = "assets"
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "assets"
    auth.audit(getattr(request.state, "user", None), "asset_exported",
               f"{len(rows)} rows",
               "selection" if ids else (urllib.parse.urlencode(filters) or "all"),
               _client_ip(request))
    return Response(buf.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{name}.csv"'})


@app.post("/assets/delete")
async def assets_bulk_delete(request: Request):
    """Remove the selected assets and come back to the same filtered view."""
    f = await request.form()
    ids = [v for v in f.getlist("ids") if v]
    back = (f.get("back") or "/assets").split("?")[0] or "/assets"
    query = (f.get("back") or "").partition("?")[2]
    me = getattr(request.state, "user", None)
    if not ids:
        return RedirectResponse(_with(back, query, err="nothing was selected"), 303)
    gone = assets.delete_many(ids)
    auth.audit(me, "assets_deleted", f"{len(gone)} asset(s)",
               ", ".join(gone[:20]) + (" …" if len(gone) > 20 else ""),
               _client_ip(request))
    word = "server" if len(gone) == 1 else "servers"
    return RedirectResponse(_with(back, query,
                                  msg=f"{len(gone)} {word} removed"), 303)


def _with(path: str, query: str, **extra) -> str:
    """A URL keeping the filters that were in force, plus a flash message."""
    parts = [p for p in query.split("&")
             if p and not p.startswith(("msg=", "err="))]
    parts += [f"{k}={urllib.parse.quote(str(v))}" for k, v in extra.items() if v]
    return path + ("?" + "&".join(parts) if parts else "")


@app.post("/assets/import")
async def asset_import(request: Request):
    """Create or update from a CSV. The same file can be uploaded twice without
    creating duplicates — rows match on serial first, hostname second."""
    import csv
    import io
    f = await request.form()
    up = f.get("file")
    if up is None or not getattr(up, "filename", ""):
        return RedirectResponse("/assets?err=choose a CSV file first", 303)
    raw = (await up.read()).decode("utf-8-sig", "replace")
    me = getattr(request.state, "user", None)
    try:
        rows = list(csv.DictReader(io.StringIO(raw)))
        res = assets.import_rows(rows, actor=(me or {}).get("email", ""))
    except Exception as e:                                    # noqa: BLE001
        return RedirectResponse(f"/assets?err=import failed: {str(e)[:120]}", 303)
    auth.audit(me, "asset_imported",
               f"{res['created']} created, {res['updated']} updated",
               " | ".join(res["errors"]), _client_ip(request))
    note = f"{res['created']} added, {res['updated']} updated"
    if res["skipped"]:
        note += f", {res['skipped']} skipped"
    if res["errors"]:
        note += f" — {len(res['errors'])} row(s) failed"
    return RedirectResponse(f"/assets?msg={note}", 303)


@app.get("/assets/{aid}", response_class=HTMLResponse)
def asset_edit_form(request: Request, aid: str, err: str = "", msg: str = "",
                    back: str = ""):
    """Edit one asset. `back` carries the list view that led here — the filters
    someone chose are theirs, and saving should not throw them away."""
    a = assets.get(aid)
    if not a:
        return RedirectResponse(_back_to(back, err="that asset no longer exists"), 303)
    return templates.TemplateResponse(
        request, "asset_form.html",
        ctx(request, asset=a, suggest=assets.suggestions(),
            attr_keys=assets.attribute_keys(), columns=assets.COLUMNS,
            project_names={k: v["name"] for k, v in store.projects().items()},
            back_to=back, err=err, msg=msg))


@app.post("/assets/new")
async def asset_create(request: Request):
    f = dict(await request.form())
    me = getattr(request.state, "user", None)
    try:
        aid = assets.create(f, actor=(me or {}).get("email", ""))
    except Exception as e:                                    # noqa: BLE001
        return RedirectResponse(f"/assets/new?err={e}", 303)
    auth.audit(me, "asset_added", f.get("hostname", ""), ip=_client_ip(request))
    return RedirectResponse(f"/assets/{aid}?msg=asset added", 303)


@app.post("/assets/{aid}")
async def asset_save(request: Request, aid: str):
    """Save and return to the list the editor came from, filters intact.

    Working down a filtered list is the normal way this page gets used, so
    landing back on the same list is the difference between one pass and
    re-picking the filter for every row.
    """
    f = dict(await request.form())
    back = f.pop("back", "")
    me = getattr(request.state, "user", None)
    try:
        assets.update(aid, f, actor=(me or {}).get("email", ""))
    except Exception as e:                                    # noqa: BLE001
        return RedirectResponse(
            f"/assets/{aid}?err={urllib.parse.quote(str(e)[:160])}"
            f"{'&back=' + urllib.parse.quote(back) if back else ''}", 303)
    auth.audit(me, "asset_updated", f.get("hostname", ""), ip=_client_ip(request))
    return RedirectResponse(
        _back_to(back, msg=f"{f.get('hostname') or 'asset'} saved"), 303)


@app.post("/assets/{aid}/delete")
async def asset_delete(request: Request, aid: str):
    f = await request.form()
    me = getattr(request.state, "user", None)
    a = assets.get(aid) or {}
    assets.delete(aid)
    auth.audit(me, "asset_removed", a.get("hostname", aid), ip=_client_ip(request))
    return RedirectResponse(
        _back_to(f.get("back", ""),
                 msg=f"{a.get('hostname') or 'asset'} removed"), 303)


def _back_to(back: str, **flash) -> str:
    """The list view to return to, with a flash message added.

    Only ever a path under /assets: a redirect target that came in on a request
    is exactly the kind of thing that turns into an open redirect if trusted.
    """
    back = back or "/assets"
    if not back.startswith("/assets") or back.startswith("//"):
        back = "/assets"
    path, _, query = back.partition("?")
    return _with(path, query, **flash)


# ── your own account ───────────────────────────────────────────
@app.get("/me", response_class=HTMLResponse)
def profile(request: Request, msg: str = "", err: str = "", enrol: str = ""):
    me = getattr(request.state, "user", None)
    if not me:
        return RedirectResponse("/login", 303)
    qr = size = None
    if enrol:
        # a fresh secret is held in the session until a code confirms it, so a
        # half-finished re-enrolment cannot lock the account out
        secret = request.session.get("reenrol_secret")
        if not secret:
            secret = auth.new_totp_secret()
            request.session["reenrol_secret"] = secret
        qr, size = auth.totp_qr(auth.totp_uri(me["email"], secret))
    mine = [a for a in auth.read_audit(limit=400)
            if a.get("user") == me.get("email")][:25]
    # Shown once and only here: held in the session rather than passed through
    # the URL, because a secret in a query string is a secret in a proxy log.
    fresh = request.session.pop("mcp_new_token", "")
    mcfg = mcp.config()
    return templates.TemplateResponse(
        request, "profile.html",
        ctx(request, me=me, mine=mine, qr=qr, qr_size=size, enrol=bool(enrol),
            ai=aiuser.shown(me["id"]), ai_providers=assistant.PROVIDERS,
            ai_shared=assistant.config(),
            mcp_on=mcfg["enabled"], mcp_days=mcfg["token_days"],
            mcp_may=rbac.may_area(me, "mcp"),
            mcp_areas=[(a, rbac.AREAS[a][0]) for a in mcp.readable_areas()],
            mcp_modes=mcp.MODE_WORDS,
            mcp_may_manage=rbac.may_area(me, "manage"),
            mcp_acts=[(n, n) for n in sorted(actions.CATALOGUE)],
            mcp_tokens=mcp.tokens(me["id"]), mcp_fresh=fresh,
            mcp_command=mcp.client_command(_mcp_base(request), fresh),
            pk_mine=passkeys.for_user(me["id"]),
            pk_ready=passkeys.readiness(_pk_base(request)),
            msg=msg, err=err))


@app.post("/me/assistant")
async def profile_assistant(request: Request):
    """Connect, change or disconnect this person's own model account.

    Their key, their bill, their choice of model — and only for their own
    questions. Nothing here touches the deployment's configuration, which is an
    administrator's to set and stays the fallback for everybody who has not
    connected one.
    """
    me = getattr(request.state, "user", None)
    if not me:
        return RedirectResponse("/login", 303)
    f = await request.form()
    if str(f.get("disconnect", "")):
        aiuser.forget(me["id"])
        # The key itself is never audited, only that one was removed.
        auth.audit(me, "assistant_account_disconnected", "",
                   ip=_client_ip(request))
        return RedirectResponse("/me?msg=your model account was disconnected", 303)
    provider = str(f.get("provider", "")).strip()
    if provider not in assistant.PROVIDERS:
        return RedirectResponse("/me?err=pick a provider", 303)
    token = str(f.get("token", "")).strip()
    if not token and not aiuser.get(me["id"]).get("token"):
        return RedirectResponse("/me?err=paste your API key to connect", 303)
    aiuser.save(me["id"], provider=provider,
                model=str(f.get("model", "")).strip(),
                token=token, base_url=str(f.get("base_url", "")).strip(),
                skip_tls=bool(f.get("skip_tls")))
    auth.audit(me, "assistant_account_connected", provider,
               ip=_client_ip(request))
    return RedirectResponse("/me?msg=your model account is connected", 303)


@app.post("/me/name")
async def profile_name(request: Request):
    me = getattr(request.state, "user", None)
    if not me:
        return RedirectResponse("/login", 303)
    f = await request.form()
    name = str(f.get("name", "")).strip()
    if not name:
        return RedirectResponse("/me?err=name cannot be empty", 303)
    auth.update_user(me["id"], name=name)
    auth.audit(me, "profile_renamed", name, ip=_client_ip(request))
    return RedirectResponse("/me?msg=name updated", 303)


@app.post("/me/password")
async def profile_password(request: Request):
    me = getattr(request.state, "user", None)
    if not me:
        return RedirectResponse("/login", 303)
    f = await request.form()
    current = str(f.get("current", ""))
    new = str(f.get("new", ""))
    again = str(f.get("again", ""))
    # the current password is required even though the session is already
    # authenticated: a hijacked session must not be able to take over the account
    if not auth.verify_password(me.get("password", ""), current):
        auth.audit(me, "password_change_denied", "wrong current password",
                   ip=_client_ip(request))
        return RedirectResponse("/me?err=current password is incorrect", 303)
    if new != again:
        return RedirectResponse("/me?err=the new passwords do not match", 303)
    problem = auth.password_problem(new)
    if problem:
        return RedirectResponse(f"/me?err={problem}", 303)
    if new == current:
        return RedirectResponse("/me?err=the new password must be different", 303)
    auth.set_password(me["id"], new)
    auth.audit(me, "password_changed", ip=_client_ip(request))
    return RedirectResponse("/me?msg=password changed", 303)


@app.post("/me/mfa")
async def profile_mfa(request: Request):
    """Re-enrol this account's authenticator.

    Requires the password *and* a code from the authenticator being replaced.
    Without the second check, anyone holding a live session could swap the
    second factor and lock the owner out.
    """
    me = getattr(request.state, "user", None)
    if not me:
        return RedirectResponse("/login", 303)
    f = await request.form()
    if not auth.verify_password(me.get("password", ""), str(f.get("current", ""))):
        auth.audit(me, "mfa_reenrol_denied", "wrong password", ip=_client_ip(request))
        return RedirectResponse("/me?err=password is incorrect", 303)
    if not auth.verify_totp(me.get("totp_secret", ""), str(f.get("code", ""))):
        auth.audit(me, "mfa_reenrol_denied", "wrong current code",
                   ip=_client_ip(request))
        return RedirectResponse("/me?err=that code did not match your current "
                                "authenticator", 303)
    request.session.pop("reenrol_secret", None)
    return RedirectResponse("/me?enrol=1", 303)


@app.post("/me/mfa/confirm")
async def profile_mfa_confirm(request: Request):
    me = getattr(request.state, "user", None)
    if not me:
        return RedirectResponse("/login", 303)
    f = await request.form()
    secret = request.session.get("reenrol_secret")
    if not secret:
        return RedirectResponse("/me?err=start the re-enrolment again", 303)
    if not auth.verify_totp(secret, str(f.get("code", ""))):
        return RedirectResponse("/me?enrol=1&err=that code did not match the new "
                                "QR — check the time on your phone", 303)
    auth.update_user(me["id"], totp_secret=secret, mfa_enrolled=True)
    request.session.pop("reenrol_secret", None)
    auth.audit(me, "mfa_reenrolled", ip=_client_ip(request))
    return RedirectResponse("/me?msg=authenticator replaced", 303)


# ── logs (display only — configuration lives in Settings) ──────
@app.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request, platform: str = "", conn: str = "", q: str = "",
              level: str = "", minutes: int = 60, refresh: str = "",
              msg: str = "", err: str = "", sec: str = ""):
    """Three levels, matching /pipelines and /security:
         /logs                            → a box per log platform in use
         ?platform=elasticsearch          → a box per connection
         ?platform=…&conn=<id>            → the search
    Searching is on demand: nothing queries a log store until you ask it to,
    because a log search is the one call here that can be genuinely expensive."""
    conns = store.all_log()
    names = {p_id: p["name"] for p_id, p in store.projects().items()}
    logstore.warm_start()   # idempotent; a hot-reloaded process warms itself
    if refresh:
        # never a blocking re-fetch: the warmer collects in the background and
        # the reload below picks it up — same contract as the Overview
        logstore.warm_now()

    present = [k for k in logstore.PROVIDERS
               if any(c.get("type") == k for c in conns)]
    if platform and platform not in present:
        platform = ""
    sel = next((c for c in conns if c["id"] == conn), None) if conn else None
    if sel and platform and sel.get("type") != platform:
        sel = None
    level = level if level in logstore.LEVELS else ""
    minutes = min(max(int(minutes or 60), 5), 60 * 24 * 7)
    level_opts, windows = logstore.LEVELS, [15, 60, 360, 1440, 10080]

    cards, block, clist = [], None, []
    if sel:
        block = {"conn": sel, "error": "", "result": None, "overview": None,
                 "scope": names.get(sel.get("pid") or "", "All projects"),
                 "provider": logstore.PROVIDERS.get(sel.get("type"), {})}
        over, remembered, _age = logstore.peek(sel)
        block["overview"] = over
        if remembered and not over:
            block["error"] = remembered
        # The window itself is the query: opening a connection shows the shape
        # of the last hour — volume, who is producing it, what repeats — because
        # "what is going on" is the question, and it cannot be typed into a
        # search box by someone who does not yet know the answer.
        if not block["error"]:
            try:
                block["result"] = logstore.explore(
                    sel, q=q, level=level, minutes=minutes,
                    limit=logstore.page_size(sel), refresh=bool(refresh))
            except Exception as e:                            # noqa: BLE001
                block["error"] = str(e)[:240]
    else:
        need = (conns if not platform
                else [c for c in conns if c.get("type") == platform])

        # cache only — the warmer owns every fetch, so this line cannot be
        # slow no matter how many stores are down
        by_id = {}
        waiting = 0
        for c in need:
            o, remembered, age = logstore.peek(c)
            if o is None and not remembered:
                waiting += 1            # the warmer has not reached it yet
            by_id[c["id"]] = (o, remembered)
        if platform:
            for c in need:
                o, error = by_id.get(c["id"], (None, ""))
                cards.append({
                    "conn": c, "provider": logstore.PROVIDERS.get(platform, {}),
                    "over": o or {}, "error": error,
                    "scope": names.get(c.get("pid") or "", "All projects"),
                    "href": f"/logs?platform={platform}&conn={c['id']}"})
        else:
            for key in present:
                mine = [c for c in conns if c.get("type") == key]
                obs = [by_id.get(c["id"], (None, ""))[0] for c in mine]
                cards.append({
                    "key": key, "provider": logstore.PROVIDERS[key], "conns": mine,
                    "streams": sum((o or {}).get("streams", 0) for o in obs),
                    "unit": next(((o or {}).get("unit") for o in obs if o), "stream"),
                    "errors": sum((o or {}).get("recent_errors") or 0 for o in obs),
                    "broken": sum(1 for c in mine if by_id.get(c["id"], (None, ""))[1]),
                    "href": f"/logs?platform={key}"})
            # a FLAT list of every connection — the hub's "All connections" and
            # "Attention" tabs (the operational-page skeleton). Cache only (peek),
            # so listing never triggers a log query.
            for c in conns:
                o, remembered = by_id.get(c["id"], (None, ""))
                o = o or {}
                clist.append({
                    "conn": c, "type": c.get("type"),
                    "provider": logstore.PROVIDERS.get(c.get("type"), {}),
                    "scope": names.get(c.get("pid") or "", "All projects"),
                    "streams": o.get("streams", 0), "unit": o.get("unit", "stream"),
                    "docs": o.get("docs", 0), "errors": o.get("recent_errors") or 0,
                    "error": remembered or "", "waiting": o == {} and not remembered,
                    "href": f"/logs?platform={c.get('type')}&conn={c['id']}"})

    return templates.TemplateResponse(
        request, "logs_search.html",
        ctx(request, level_name="logs", cards=cards, block=block, conns=conns,
            present=present, providers=logstore.PROVIDERS, platform=platform,
            sel=sel, q=q, level=level, minutes=minutes, windows=windows,
            level_opts=level_opts,
            level_stage=("search" if sel else "provider" if platform else "hub"),
            waiting=0 if sel else (waiting or bool(refresh)),
            sec=sec, clist=clist,
            alist=[x for x in clist if x["error"] or x["errors"]],
            n_errors=sum(x["errors"] for x in clist),
            n_broken=sum(1 for x in clist if x["error"]),
            n_attn=sum(1 for x in clist if x["error"] or x["errors"]),
            msg=msg, err=err))


# ── log connection management (Settings) ───────────────────────
def _log_from_form(f) -> dict:
    return {"skip_tls": f.get("skip_tls") == "on",
            "type": str(f.get("type", "")).strip(),
            "name": str(f.get("name", "")).strip(),
            "base_url": str(f.get("base_url", "")).strip().rstrip("/"),
            "scope": str(f.get("scope", "")).strip(),
            "username": str(f.get("username", "")).strip(),
            "tenant": str(f.get("tenant", "")).strip(),
            "limit": str(f.get("limit", "")).strip(),
            "f_time": str(f.get("f_time", "")).strip(),
            "f_level": str(f.get("f_level", "")).strip(),
            "f_message": str(f.get("f_message", "")).strip(),
            "f_service": str(f.get("f_service", "")).strip()}


@app.post("/settings/log/new")
async def log_new(request: Request):
    f = await request.form()
    conn = _log_from_form(f)
    conn["token"] = str(f.get("token", ""))
    pid = str(f.get("pid", ""))
    if conn["type"] not in logstore.PROVIDERS:
        return back(err="choose a log platform", to="/settings/logs")
    prov = logstore.PROVIDERS[conn["type"]]
    if not conn["name"]:
        conn["name"] = prov["label"]
    missing = [k for k in prov["needs"] if not conn.get(k)]
    if missing:
        return back(err=f"missing for {prov['label']}: {', '.join(missing)}",
                    to="/settings/logs")
    ok, detail = await run_in_threadpool(logstore.test, conn)
    conn["status"] = ("ok: " if ok else "failed: ") + detail
    store.add_log(pid, conn)
    auth.audit(getattr(request.state, "user", None), "logs_connected",
               f"{conn['type']}:{conn['name']}", detail, _client_ip(request))
    return (back(msg=f"{conn['name']} — {detail}", to="/settings/logs")
            if ok else back(err=detail, to="/settings/logs"))


@app.post("/settings/log/{cid}/update")
async def log_update(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    fields = _log_from_form(f)
    fields.pop("type", None)
    if str(f.get("token", "")):
        fields["token"] = str(f.get("token"))
    store.update_log(pid, cid, **fields)
    logstore.invalidate()
    ok, detail = await run_in_threadpool(logstore.test, store.get_log(pid, cid) or {})
    store.update_log(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/logs") if ok
            else back(err=detail, to="/settings/logs"))


@app.post("/settings/log/{cid}/test")
async def log_test(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    ok, detail = await run_in_threadpool(logstore.test, store.get_log(pid, cid) or {})
    store.update_log(pid, cid, status=("ok: " if ok else "failed: ") + detail)
    return (back(msg=detail, to="/settings/logs") if ok
            else back(err=detail, to="/settings/logs"))


@app.post("/settings/log/{cid}/delete")
async def log_delete(request: Request, cid: str):
    f = await request.form()
    pid = str(f.get("pid", ""))
    name = (store.get_log(pid, cid) or {}).get("name", cid)
    store.delete_log(pid, cid)
    logstore.invalidate()
    auth.audit(getattr(request.state, "user", None), "logs_removed", name,
               ip=_client_ip(request))
    return back(msg="connection removed", to="/settings/logs")


# Registered last on purpose: middleware added later wraps earlier ones, so this
# must come after require_login for request.session to exist inside the gate.
# lifetime and the HTTPS-only flag are deployment decisions: behind a TLS
# ingress the cookie should refuse to travel in clear, and how long a session
# lasts is a policy, not a constant
app.add_middleware(SessionMiddleware, secret_key=auth.session_secret(),
                   session_cookie="portal_session",
                   max_age=int(env.SESSION_HOURS * 3600),
                   same_site="lax", https_only=env.COOKIE_SECURE)


@app.on_event("startup")
def _check_route_shadowing():
    """Refuse to start if a catch-all route hides a specific one.

    A generic /settings/{kind}/new once shadowed /settings/stor/new and five
    others: FastAPI takes the first registered match, so those POSTs were
    swallowed and answered with a bare redirect — no error, no log line, just a
    form that quietly did nothing. Registration order is invisible in the source,
    so it is checked here instead of trusted.
    """
    import re as _re
    paths = [(r.path, tuple(sorted((getattr(r, "methods", None) or set()) - {"HEAD"})))
             for r in app.routes if getattr(r, "path", None)]
    clashes = []
    for i, (g, gm) in enumerate(paths):
        if "{" not in g:
            continue
        pat = _re.compile("^" + _re.sub(r"\{[^}]+\}", "[^/]+", g) + "$")
        for j, (p, pm) in enumerate(paths):
            if j <= i or "{" in p or not pat.match(p):
                continue
            if set(gm) & set(pm):
                clashes.append(f"{g} {gm} hides {p} {pm}")
    if clashes:
        raise RuntimeError(
            "route shadowing — a parameterised route is registered before a "
            "specific one it matches, so the specific handler can never run:\n  "
            + "\n  ".join(clashes))
