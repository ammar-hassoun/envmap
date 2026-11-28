# Contributing to DevOps EnvMap

Thank you for taking the time. Bug reports, ideas and pull requests are all welcome.

## Where things go

| You have | Put it here |
|---|---|
| A question, or "how do I…" | [Discussions, Q&A](https://github.com/ammar-hassoun/envmap/discussions) |
| An idea or a request | [Discussions, Ideas](https://github.com/ammar-hassoun/envmap/discussions), or an issue if it is specific |
| Something that is broken | [An issue](https://github.com/ammar-hassoun/envmap/issues/new/choose) |
| A security problem | A private report. See [SECURITY.md](SECURITY.md). Never a public issue |

## A good bug report

Say what you did, what you expected and what happened instead. Add:

- the EnvMap version (the sidebar shows it, and so does `/healthz`);
- how it is installed: Helm or Docker Compose, and the mode (`full` or `pam`);
- the system involved (for example Argo CD 3.1, Proxmox 9, an RDP target);
- the message on the page, or the lines from the portal's log.

Remove hostnames, tokens and anything else private before you post.

## Running it from source

You need Python 3.11 or newer, `git` and `kubectl`. The
[reference](docs/REFERENCE.md#running-it-locally) lists what each optional tool
adds.

```bash
git clone https://github.com/ammar-hassoun/envmap.git
cd envmap
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
./.venv/bin/uvicorn app.main:app --port 8471 --reload
```

Open <http://localhost:8471>. State goes to `data/` beside the code unless you
set `PORTAL_DATA_DIR`.

## Tests

The tests are plain Python scripts, not pytest. Each prints `OK` or `N FAILED`
and exits non-zero on failure:

```bash
for t in tests/test_*.py; do ./.venv/bin/python "$t"; done
```

## Sending a change

1. Open an issue or a discussion first for anything larger than a small fix, so
   nobody builds something that cannot be merged.
2. Keep a pull request to one change.
3. Add a test, and check that it is load-bearing: it must fail without your
   change and pass with it.
4. Say in the pull request what you ran and what you saw.

Rules the code holds itself to, which a change must keep:

- **Nothing about one estate is in the code.** Names, hostnames, networks and
  key prefixes are configuration. `tests/test_nohardcoding.py` checks it.
- **Read-only first.** A new integration reads. Anything that writes is
  switched on separately and granted to a role.
- **"None" and "could not ask" never look the same.** A failed read is an
  error on the page, never an empty list or a zero.
- **No inline event handlers and no script without the page's nonce.** The
  Content-Security-Policy refuses both. `tests/test_csp.py` sweeps for them.
- **Escape everything a system or a person typed** before it reaches a page.

## How a merged change reaches this repository

DevOps EnvMap is developed in a private repository against real estates, and
this repository is published from it, one commit for each release. A pull
request accepted here is applied there by the maintainer, with you credited in
the commit, and arrives here with the next release. Your pull request is then
closed with a link to that release.

## Licence

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), the licence of the project.
