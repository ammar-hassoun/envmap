"""PORTAL_MODE=pam: the installation is Privileged Access and nothing else.

What is proved, for an administrator as well as an operator, because an
administrator holds every area and is the one a missed check would show
everything to:

    * the landing page is the PAM, not an Overview
    * the sidebar has the PAM, Users, Roles, the audit log and Settings, and
      no link to any other part of the product
    * every other part is refused when its URL is typed, not merely unlinked
    * Settings lists and serves only the PAM's, the mail relay's and the
      deployment's pages
    * the PAM is on whatever its stored switch says, and saving its settings
      does not rewrite that switch
    * the role editor offers only the PAM's areas, and saving a role there
      keeps the areas, projects and clusters it could not show -- an empty
      project list means "every project", so losing it would widen the role
      the day the mode goes back to full
    * a mode that is neither full nor pam stops the process at start

    ./.venv/bin/python tests/test_pam_only_mode.py
"""
import json
import os
import subprocess
import sys
import time

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("pamonly-")
os.environ["PORTAL_MODE"] = "pam"
os.environ.pop("PORTAL_PAM", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import auth, db, env, main, pam, rbac  # noqa: E402

bad = 0

OTHER_PAGES = ["/clusters", "/compare", "/repos", "/timeline", "/expiry",
               "/certs", "/edge", "/pipelines", "/gitops", "/workflows",
               "/security", "/logs", "/monitoring", "/ansible", "/terraform",
               "/db", "/vpn", "/assets", "/bmc", "/virt", "/clouds",
               "/storage", "/spend", "/search?q=x"]
OTHER_LINKS = ['href="/clusters"', 'href="/compare"', 'href="/timeline"',
               'href="/expiry"', 'href="/certs"', 'href="/ansible"',
               'href="/terraform"', 'href="/settings/projects"',
               'action="/search"', 'href="/assets"', 'href="/logs"']


def check(what: str, ok: bool) -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok   " if ok else "  FAIL ") + what)


def enrol(email: str, pw: str, role: str = "viewer", areas=None) -> str:
    uid = auth.create_user(email, "N", pw, role=role)
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
           "email_verified=1 WHERE id=?", ("TESTSECRET", uid))
    if areas:
        rid = rbac.save("", email.split("@")[0], "", areas, [], [], [])
        rbac.set_for_user(uid, [rid])
    return uid


def signed_in(email: str, pw: str) -> TestClient:
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def lands(c: TestClient, path: str) -> tuple[int, str]:
    r = c.get(path, follow_redirects=False)
    return r.status_code, r.headers.get("location", "")


def main_test() -> int:
    check(f"the mode is read, got {env.MODE!r}", env.pam_only())
    check("the PAM is on although its stored switch is off",
          pam.enabled() and not pam.config()["enabled"])

    enrol("admin@t.local", "Admin-PamOnly-1", role="admin")
    enrol("op@t.local", "Op-PamOnly-1", areas=["pam", "pam_connect"])
    admin = signed_in("admin@t.local", "Admin-PamOnly-1")
    op = signed_in("op@t.local", "Op-PamOnly-1")

    for who, c in (("an administrator", admin), ("an operator", op)):
        print(f"{who} lands on the PAM")
        st, loc = lands(c, "/")
        check(f"/ goes to /pam, got {st} {loc}", st == 303 and loc == "/pam")
        r = c.get("/pam")
        check(f"/pam opens, got {r.status_code}", r.status_code == 200)
        side = r.text
        check("the sidebar has Privileged Access", 'href="/pam"' in side)
        leaks = [l for l in OTHER_LINKS if l in side]
        check(f"and no link to the rest of the product, found {leaks}",
              not leaks)
        check("and no Projects list", "projnav" not in side)

    print("everything else is refused, an administrator included")
    for path in OTHER_PAGES:
        st, _ = lands(admin, path)
        check(f"{path} is refused, got {st}", st == 403)
    page = admin.get("/clusters").text
    check("the refusal says the part is not here, not to ask for a role",
          "is not part of this installation" in page
          and "An administrator can add one" not in page)
    check("and leads back to the PAM, not to an Overview",
          'href="/pam">← Back to Privileged Access' in page
          and "Back to overview" not in page)
    st, _ = lands(admin, "/overview/layout")
    check(f"the overview's own endpoint goes too, got {st}", st == 303)

    print("users, roles, the audit log and your own account stay")
    for path in ("/admin/users", "/admin/roles", "/admin/audit", "/me",
                 "/about", "/healthz"):
        st, _ = lands(admin, path)
        check(f"{path} opens, got {st}", st == 200)
    side = admin.get("/pam").text
    for link in ('href="/admin/users"', 'href="/admin/roles"',
                 'href="/admin/audit"', 'href="/settings"'):
        check(f"the sidebar has {link}", link in side)

    print("Settings keeps the PAM's pages and nothing else")
    hub = admin.get("/settings").text
    for k in ("pam", "mail", "deployment"):
        check(f"the hub lists /settings/{k}", f'href="/settings/{k}"' in hub)
    for k in ("clusters", "projects", "pipelines", "mcp", "ansible",
              "terraform", "logs", "conns/edge"):
        check(f"the hub does not list /settings/{k}",
              f'href="/settings/{k}"' not in hub)
    for path in ("/settings/clusters", "/settings/projects", "/settings/mcp",
                 "/settings/conns/edge", "/setup"):
        st, loc = lands(admin, path)
        check(f"{path} goes back to Settings, got {st} {loc}",
              st == 303 and loc == "/settings")
    for path in ("/settings/pam", "/settings/mail", "/settings/deployment"):
        st, _ = lands(admin, path)
        check(f"{path} opens, got {st}", st == 200)
    page = admin.get("/settings/pam").text
    check("the PAM page says it is always on here",
          "this installation is Privileged Access only" in page
          and 'name="enabled"' not in page)
    check("the deployment page shows the mode",
          "PORTAL_MODE" in admin.get("/settings/deployment").text)

    print("saving the PAM's settings leaves its stored switch alone")
    admin.post("/settings/pam", data={"record_sessions": "1"},
               follow_redirects=False)
    check("the stored switch is still off, and the PAM still on",
          not pam.config()["enabled"] and pam.enabled())

    print("the assistant does not exist here")
    r = admin.post("/assistant/ask", json={"q": "hello"})
    check(f"/assistant/ask answers 404, got {r.status_code}",
          r.status_code == 404)

    print("the role editor offers the PAM's areas only")
    page = admin.get("/admin/roles").text
    check("it offers Privileged Access: connect",
          'name="areas" value="pam_connect"' in page)
    check("it does not offer Clusters or Settings-free extras",
          'name="areas" value="clusters"' not in page
          and 'name="areas" value="overview"' not in page)
    check("and has no project or cluster pickers",
          'name="projects"' not in page and 'name="clusters"' not in page)

    print("saving a role keeps what the editor could not show")
    db.run("INSERT INTO roles (id, name, note, areas, projects, clusters, "
           "targets, created) VALUES (?,?,?,?,?,?,?,?)",
           ("r-mixed", "mixed", "", json.dumps(["clusters", "pam"]),
            json.dumps(["p-kenya"]), json.dumps(["c-1"]), json.dumps([]),
            "2026-11-10 00:00:00"))
    admin.post("/admin/roles/save",
               data={"rid": "r-mixed", "name": "mixed",
                     "areas": ["pam_connect", "clusters"]},
               follow_redirects=False)
    got = rbac.get("r-mixed")
    check(f"the PAM area ticked is saved, got {got['areas']}",
          "pam_connect" in got["areas"] and "pam" not in got["areas"])
    check("the hidden Clusters area is kept", "clusters" in got["areas"])
    check(f"the projects are kept, got {got['projects']}",
          got["projects"] == ["p-kenya"])
    check(f"and the clusters, got {got['clusters']}",
          got["clusters"] == ["c-1"])
    check("a kept area outside the PAM still opens nothing",
          not rbac.may_area({"id": "x", "role": "admin"}, "clusters"))

    print("a mode that is neither stops the process")
    p = subprocess.run(
        [sys.executable, "-c", "import app.env"], cwd=ROOT,
        env={**os.environ, "PORTAL_MODE": "pam-only"},
        capture_output=True, text=True)
    check(f"it exits non-zero, got {p.returncode}", p.returncode != 0)
    check("and says what the choices are",
          "must be one of: full, pam" in (p.stderr + p.stdout))

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main_test() else 0)
