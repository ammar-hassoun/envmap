"""Standard operating procedures — the runbooks a terminal shows beside the shell.

An SOP is a title, a one-line summary, some tags and a body of markdown-lite.
A `#` or `##` heading in the body starts a numbered step, a ``` fence is a
command, and an UPPER_CASE `{{NAME}}` inside one is a value the operator fills
in once for every command (see _sop.html). They live in the database like the
rest of this portal's configuration.

WRITING ONE IS ITS OWN GRANT (`pam_sops`), and an escalating one: what an SOP
says is pasted into production shells by people who trust it, so changing an
SOP is changing what they will run -- on targets the writer may have no access
to. Deleting one is `pam_delete` on top, like every other PAM record.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
import uuid
from datetime import datetime, timezone

from . import db, rbac
from .ansible import Refused

TITLE_MAX = 120
SUMMARY_MAX = 240
BODY_MAX = 64_000
TAGS_MAX = 12
TAG_OK = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,31}$")

# Never part of a runbook somebody pastes from: every control character but
# tab and newline, and every FORMAT character. A control can act on the shell
# instead of being text in it -- ESC [ 201 ~ ends a bracketed paste early, and
# the CR after it presses Enter on the operator's behalf -- and the format
# characters are the invisible and direction-changing ones that make a command
# READ differently from what it RUNS ("Trojan Source": U+202E, U+061C, a soft
# hyphen, the tag block). By category rather than a list, so none is missed;
# _sop.html strips the same two categories before a paste.
def _hidden(ch: str) -> bool:
    return ch not in "\t\n" and unicodedata.category(ch) in ("Cc", "Cf")


def _strip(text: str, put: str = "") -> str:
    return "".join(put if _hidden(ch) else ch for ch in text)


# A placeholder: an UPPER_CASE name in double braces (see _sop.html).
_HOLE = re.compile(r"\{\{([A-Z][A-Z0-9_]{0,31})\}\}")
# A value filled into a placeholder is typed into the command line, so the
# shell echoes it and the recording and the audit log keep it for ever. A
# secret must be asked for by the command (mysql -p, read -s), never by the
# SOP -- the same words the recorder treats as a password prompt
# (kmanage.SECRET_PROMPT), matched as whole parts of the name so KEY_PATH is
# still a path.
_SECRETISH = re.compile(r"(?:^|_)(?:PASS(?:WORD|WD|PHRASE)?|SECRET|TOKEN|API_?KEY|"
                        r"PRIVATE_KEY|ACCESS_KEY|PIN|OTP|MFA|2FA|CREDENTIALS?)(?:_|$)")

WRITE_NEEDS = "writing an SOP needs “Privileged Access: write SOPs”"
DELETE_NEEDS = ("deleting an SOP needs “Privileged Access: write SOPs” and "
                "“Privileged Access: delete”")

# A step heading: `#` or `##`. Deeper headings stay inside the step they are
# in. A leading "1." or "Step 2:" is dropped, because the steps are numbered
# for the reader and a body renumbered by hand drifts.
_STEP = re.compile(r"^#{1,2}\s+(.+?)\s*#*$")
_NUMBERED = re.compile(r"^(?:step\s*)?\d+\s*[.):-]\s*", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean(text) -> str:
    """The body as stored: one kind of newline, nothing hidden in it."""
    return _strip(str(text or "").replace("\r\n", "\n").replace("\r", "\n"))


def why_not(user, action: str = "write") -> str:
    """'' when this person may write -- or, action='delete', delete -- SOPs;
    otherwise the reason. The ONE rule: the handlers refuse with it and every
    page that offers the button disables it with it."""
    if not rbac.may_area(user, "pam_sops"):
        return DELETE_NEEDS if action == "delete" else WRITE_NEEDS
    if action == "delete" and not rbac.may_area(user, "pam_delete"):
        return DELETE_NEEDS
    return ""


def fingerprint(body) -> str:
    """Which version of a body this was, for the audit line of a save."""
    return hashlib.sha256(str(body or "").encode()).hexdigest()[:16]


def tags_of(raw) -> list:
    """`TLS, nginx  lb` -> ['tls', 'nginx', 'lb']."""
    got: list = []
    for tag in re.split(r"[,\s]+", str(raw or "").lower()):
        if not tag or tag in got:
            continue
        if not TAG_OK.match(tag):
            raise Refused(f"{tag!r} is not a tag — letters, digits, dot, "
                          "dash, colon or underscore, at most 32")
        got.append(tag)
    if len(got) > TAGS_MAX:
        raise Refused(f"{TAGS_MAX} tags at most")
    return got


def _day(iso: str) -> str:
    """'2026-10-01T09:30:00+00:00' -> '1 October 2026'."""
    try:
        d = datetime.fromisoformat(iso or "")
    except ValueError:
        return ""
    return f"{d.day} {d:%B %Y}"


def _row(r) -> dict:
    d = dict(r)
    d["tags"] = [t for t in (d.get("tags") or "").split(",") if t]
    body = d.get("body") or ""
    d["step_count"] = len(_split(body)[1])
    d["command_count"] = _commands(body)
    d["updated_day"] = _day(d.get("updated") or "")
    # for the table sorter, which reads "1 October" as the number 1
    d["updated_sort"] = re.sub(r"\D", "", (d.get("updated") or "")[:19])
    return d


def every() -> list:
    return [_row(r) for r in db.q(
        "SELECT * FROM sops ORDER BY title COLLATE NOCASE")]


def count() -> int:
    return db.one("SELECT COUNT(*) AS n FROM sops")["n"]


def one(sid: str) -> dict | None:
    r = db.one("SELECT * FROM sops WHERE id = ?", (sid,))
    return _row(r) if r else None


def save(sid: str, fields: dict, who: str) -> str:
    """Create or update one SOP; Refused names what is wrong with it."""
    title = " ".join(_strip(str(fields.get("title") or ""), " ").split())
    if not title:
        raise Refused("an SOP needs a title")
    if len(title) > TITLE_MAX:
        raise Refused(f"a title is {TITLE_MAX} characters at most")
    summary = " ".join(_strip(str(fields.get("summary") or ""), " ").split())
    if len(summary) > SUMMARY_MAX:
        raise Refused(f"a summary is {SUMMARY_MAX} characters at most")
    tags = ",".join(tags_of(fields.get("tags")))
    body = clean(fields.get("body")).strip("\n")
    if not body.strip():
        raise Refused("an SOP needs a body — at least one step")
    if len(body) > BODY_MAX:
        raise Refused(f"a body is {BODY_MAX // 1000} KB at most")
    secret = sorted({n for n in _HOLE.findall(body) if _SECRETISH.search(n)})
    if secret:
        raise Refused(
            "{{" + secret[0] + "}} asks for a secret — a value filled in there is "
            "typed into the command line, so the shell echoes it and the "
            "recording keeps it. Let the command ask for it instead "
            "(mysql -p, read -s)")
    now = _now()
    with db.tx() as c:
        # One name, one procedure: two SOPs called the same thing in the side
        # panel is a coin toss for whoever is fixing production at the time.
        twin = c.execute("SELECT id FROM sops WHERE title = ? COLLATE NOCASE "
                         "AND id != ?", (title, sid or "")).fetchone()
        if twin:
            raise Refused(f"there is already an SOP called {title!r}")
        if sid:
            if not c.execute(
                    "UPDATE sops SET title=?, summary=?, tags=?, body=?, "
                    "updated=?, updated_by=? WHERE id=?",
                    (title, summary, tags, body, now, who, sid)).rowcount:
                raise Refused("that SOP is gone")
        else:
            sid = "sop-" + uuid.uuid4().hex[:12]
            c.execute("INSERT INTO sops (id, title, summary, tags, body, "
                      "created, created_by, updated, updated_by) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (sid, title, summary, tags, body, now, who, now, who))
    return sid


def delete(sid: str) -> bool:
    with db.tx() as c:
        return bool(c.execute("DELETE FROM sops WHERE id = ?", (sid,)).rowcount)


def _split(body: str):
    """(intro lines, [(title, lines)]) -- a `#` inside a fence is a shell
    comment, not a step. Takes a body clean() has already been through: every
    stored one has, and the preview cleans what it is sent."""
    intro: list = []
    steps: list = []
    fence = False
    for line in str(body or "").split("\n"):
        s = line.strip()
        if s.startswith("```"):
            fence = not fence
        elif not fence and (m := _STEP.match(s)):
            steps.append((_NUMBERED.sub("", m.group(1)).strip() or m.group(1),
                          []))
            continue
        (steps[-1][1] if steps else intro).append(line)
    return intro, steps


def _commands(body: str) -> int:
    opens = [ln.strip() for ln in str(body or "").split("\n")
             if ln.strip().startswith("```")][::2]
    return sum(1 for o in opens if is_command(o[3:].strip()))


# The fence languages that are a COMMAND, offered for pasting at the prompt.
# Anything else -- output, a config file, YAML, a `console` transcript with its
# prompts in it -- can be copied but is not typed into a shell for somebody.
# _sop.html holds the same list for the buttons.
SHELLS = ("", "sh", "bash", "shell", "zsh")


def is_command(lang: str) -> bool:
    return (lang or "").strip().lower() in SHELLS


def steps(body: str, mdlite) -> dict:
    """The body rendered as an intro and numbered steps:
    {"intro": Markup, "steps": [{"title": str, "html": Markup}]}.

    `mdlite` is the portal's escape-first renderer, passed in the way
    grafview takes it, so an SOP is exactly as safe to render as a scanner's
    advisory."""
    intro, parts = _split(body)
    return {"intro": mdlite("\n".join(intro)) if "".join(intro).strip() else "",
            "steps": [{"title": t, "html": mdlite("\n".join(lines))}
                      for t, lines in parts]}


# ── the worked example ────────────────────────────────────────
# Written into a database ONCE, when this table is first created there -- so
# a new installation shows what an SOP looks like, and one somebody deleted
# does not come back on the next start. Generic on purpose: it finds the files
# NGINX actually uses rather than assuming a layout, and every path is a value
# the operator fills in.
EXAMPLE = {
    "title": "Renew a TLS certificate on an NGINX load balancer",
    "summary": ("Issue it in Certificates, prove the domain with a DNS record, "
                "then find, back up and replace the files on the load balancer, "
                "test, reload and check with curl. A worked example — check it "
                "against your hosts before relying on it."),
    "tags": "tls, certificate, renewal, nginx, lb",
    "body": """\
For a certificate NGINX serves on a load balancer. Steps 1 and 2 happen in \
the browser and step 5 in the **⇅ Files** window; every command runs here in \
the terminal, on the load balancer, and nothing runs until you press Enter. \
Fill in the values above once — every command uses them.

When more than one load balancer serves the name, do steps 3 to 10 on each — \
one terminal tab per load balancer, opened with **New session**.

## Create the certificate in Certificates
Open the certificate that is expiring and choose **Renew** — or \
**＋ New certificate** for a name that has not been issued here before. The \
next page shows the DNS record to add.

## Add the DNS record, then download the certificate
Add the record shown — name `_acme-challenge.…`, type TXT, the value as \
given — at your DNS provider, with the lowest TTL it allows. A wildcard and \
its base name share one record name with two values: add both, do not replace \
one with the other. Choose **The records are in — carry on without me**, and \
when the certificate is issued download the **full chain** and the **private \
key** to your computer. Both are named after the certificate, and that name is CERT_NAME — a \
wildcard `*.example.com` downloads as `wildcard.example.com`.

## Find the certificate files on the load balancer
What NGINX actually loads, file by file: in the server block for DOMAIN, \
`ssl_certificate` is CERT_PATH and `ssl_certificate_key` is KEY_PATH.
```
nginx -T 2>/dev/null | grep -nE "^# configuration file|server_name|ssl_certificate"
```
Or search the configuration files themselves:
```
grep -rnE "^\\s*(server_name|ssl_certificate|ssl_certificate_key)\\s" /etc/nginx/
```

## Back up the current files
Dated, beside the originals; `cp -a` keeps their owner, mode and SELinux label.
```
cp -a {{CERT_PATH}} {{CERT_PATH}}.bak-$(date +%F) && cp -a {{KEY_PATH}} {{KEY_PATH}}.bak-$(date +%F)
```

## Upload the new files from your computer
With **⇅ Files** at the top of this page: type `/tmp` in the path bar and \
press Enter, then choose **⇧ upload** and pick both files you downloaded in \
step 2 — `{{CERT_NAME}}.fullchain.pem` and `{{CERT_NAME}}.privkey.pem` — or \
drag them onto the list. Wait until both show as done, then close the window.

## Check the new files, then replace the old ones
The certificate must name DOMAIN and be in date, and the two hashes printed \
last must be identical — the key belongs to the certificate.
```
openssl x509 -in /tmp/{{CERT_NAME}}.fullchain.pem -noout -subject -enddate; openssl x509 -in /tmp/{{CERT_NAME}}.fullchain.pem -noout -pubkey | sha256sum; openssl pkey -in /tmp/{{CERT_NAME}}.privkey.pem -pubout | sha256sum
```
Then copy them over the old files. Copy, never move: a file moved out of \
`/tmp` keeps the /tmp SELinux label and NGINX cannot read it. Answer `y` if \
`cp` asks to overwrite.
```
cp /tmp/{{CERT_NAME}}.fullchain.pem {{CERT_PATH}} && cp /tmp/{{CERT_NAME}}.privkey.pem {{KEY_PATH}}
```

## Test the configuration
It must say the test is successful. If it does not, do not reload — put the \
backup back (the last step).
```
nginx -t
```

## Reload NGINX
Open connections are kept; nothing restarts.
```
nginx -s reload
```

## Check the new certificate with curl
Asks this load balancer itself for DOMAIN and prints the certificate it now \
serves — the expire date is the new one. If NGINX listens on one address \
only, use it in place of 127.0.0.1.
```
curl -sv --resolve {{DOMAIN}}:443:127.0.0.1 https://{{DOMAIN}}/ -o /dev/null 2>&1 | grep -E "subject:|issuer:|expire date:|SSL certificate verify"
```
And through DNS, as a client sees it:
```
curl -sv https://{{DOMAIN}}/ -o /dev/null 2>&1 | grep -E "subject:|expire date:|SSL certificate verify"
```

## Remove the uploaded copies
The private key must not stay in /tmp.
```
rm -f /tmp/{{CERT_NAME}}.fullchain.pem /tmp/{{CERT_NAME}}.privkey.pem
```

## If something went wrong
Put today's backups back, test, and reload.
```
cp -a {{CERT_PATH}}.bak-$(date +%F) {{CERT_PATH}} && cp -a {{KEY_PATH}}.bak-$(date +%F) {{KEY_PATH}} && nginx -t && nginx -s reload
```""",
}


def _migrate(c) -> None:
    fresh = not c.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' "
                          "AND name = 'sops'").fetchone()
    c.execute("""CREATE TABLE IF NOT EXISTS sops (
        id TEXT PRIMARY KEY, title TEXT NOT NULL, summary TEXT DEFAULT '',
        tags TEXT DEFAULT '', body TEXT DEFAULT '',
        created TEXT, created_by TEXT, updated TEXT, updated_by TEXT)""")
    if fresh:
        now = _now()
        c.execute("INSERT INTO sops (id, title, summary, tags, body, created, "
                  "created_by, updated, updated_by) "
                  "VALUES (?, ?, ?, ?, ?, ?, '', ?, '')",
                  ("sop-example-tls", EXAMPLE["title"], EXAMPLE["summary"],
                   ",".join(tags_of(EXAMPLE["tags"])), EXAMPLE["body"],
                   now, now))


db.register(_migrate)
