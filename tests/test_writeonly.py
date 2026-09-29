#!/usr/bin/env python3
"""An empty field must clear the field — except where it would destroy a secret.

WHY THIS EXISTS
    update_conn() applied "blank means keep what is stored" to EVERY field. That
    rule is needed for exactly one kind of field: the ones whose stored value is
    never rendered back, which submit empty when the user does not touch them.
    Applied to all of them, nothing optional could ever be cleared.

    It surfaced on Bitbucket. An access token has no user and must be sent as
    Bearer, which app/ci.py decides by the username being blank — so blanking it
    was the whole mechanism, and blanking it silently kept the old value. The
    field refilled itself on save, which reads as the form ignoring you.

    Both halves are tested, because each is a way to lose data: one loses a
    credential, the other loses the ability to change a setting.

    ./.venv/bin/python tests/test_writeonly.py
"""
from __future__ import annotations

import os
import pathlib
import re
import sys

import _sandbox                                                # noqa: E402
os.environ["PORTAL_DATA_DIR"] = _sandbox.data_dir("writeonly-test-")
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import ci, store                                      # noqa: E402

bad = 0


def check(what: str, cond: bool) -> None:
    global bad
    if not cond:
        bad += 1
        print(f"  FAIL {what}")


def field(cid: str, name: str):
    row = [c for c in store.all_conns("ci") if c["id"] == cid][0]
    return row.get(name)


def main() -> int:
    cid = store.add_conn("ci", store.GLOBAL,
                         {"name": "BB", "type": "bitbucket",
                          "repo": "acme",
                          "username": "x-bitbucket-api-token-auth",
                          "token": "ATCTT-original"})

    print("a blank secret keeps what is stored")
    # The input never showed it, so submitting the form untouched must not be
    # the same gesture as deleting the credential.
    store.update_conn("ci", store.GLOBAL, cid, repo="acme-2", token="")
    check("the token survived an unrelated edit",
          field(cid, "token") == "ATCTT-original")
    check("and the edit itself applied", field(cid, "repo") == "acme-2")

    print("but a blank ordinary field clears it")
    store.update_conn("ci", store.GLOBAL, cid, username="")
    check(f"username is empty, got {field(cid, 'username')!r}",
          field(cid, "username") == "")
    check("clearing the username did not touch the token",
          field(cid, "token") == "ATCTT-original")

    print("and that is what selects Bearer for a Bitbucket access token")
    # The regression, end to end: an access token authenticates with no user,
    # and a project token used as Basic gets a 401 from Bitbucket.
    row = [c for c in store.all_conns("ci") if c["id"] == cid][0]
    auth = ci._bb_auth(row)
    check(f"header is Bearer, got {auth}",
          auth.get("Authorization", "").startswith("Bearer "))
    check("an app password still authenticates as Basic",
          ci._bb_auth({"username": "me", "token": "p"})
          .get("Authorization", "").startswith("Basic "))
    check("a username is no longer required to save the connection",
          "username" not in ci.PROVIDERS["bitbucket"]["needs"])

    print("a secret can still be replaced, and re-cleared to nothing")
    store.update_conn("ci", store.GLOBAL, cid, token="ATCTT-new")
    check("replacement applied", field(cid, "token") == "ATCTT-new")

    print("no write-only input on a connection form is missing from the list")
    # Two files hold this knowledge: the template decides a field is write-only,
    # the store protects it. A field added to one and not the other loses a
    # credential silently, so the drift is what is being tested.
    action = re.compile(r'action="/settings/(' + "|".join(store.CONN_KINDS)
                        + r')/\{\{[^}]*\}\}/update"')
    seen = set()
    for tpl in sorted((ROOT / "templates").glob("*.html")):
        body = tpl.read_text()
        # forms are not nested, so each chunk after a <form is one form
        for chunk in body.split("<form")[1:]:
            if not action.search(chunk):
                continue
            for tag in re.findall(r"<input[^>]*>", chunk):
                if 'type="password"' not in tag:
                    continue
                m = re.search(r'name="([a-z_]+)"', tag)
                if m:
                    seen.add((tpl.name, m.group(1)))
    check("the scan found the forms at all — a silent zero would pass",
          len(seen) >= 4)
    for where, name in sorted(seen):
        check(f"{where} writes {name!r}, which store.WRITE_ONLY omits",
              name in store.WRITE_ONLY)

    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
