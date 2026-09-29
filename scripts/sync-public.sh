#!/usr/bin/env bash
# Publish this repository's HEAD to the PUBLIC mirror.
#
# Two repositories hold one product. This one is private and keeps the full
# history; github.com/ammar-hassoun/envmap is public and keeps NO history at
# all — it is rebuilt as a single commit every time, so nothing that was ever
# excluded can be recovered from it by reading an older revision.
#
# THE EXCLUSION LIST IS THE POINT. A file kept out by hand is a file that gets
# published the first time somebody syncs in a hurry, so it lives here and the
# script is the only supported way to push the mirror.
set -euo pipefail

PUBLIC_REMOTE="https://github.com/ammar-hassoun/envmap.git"
WORK="${TMPDIR:-/tmp}/envmap-public-sync"

# Never leaves this repository:
#   CLAUDE.md          the engineering guide — written for whoever works on
#                      this with the full history and the private operational
#                      notes in hand
#   .claude/           agent definitions and the local launch config
#   security/          the dated sweep reports are an INVENTORY OF UNFIXED
#                      WEAKNESSES in software that runs in other people's
#                      clusters, and scan.sh's raw scanner output with them.
#                      They were safe to track when this repository was
#                      private; they are the single worst thing here to
#                      publish. Nearly went out in the 0.7.30 commit.
EXCLUDE=(CLAUDE.md .claude security)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

[ -z "$(git status --porcelain)" ] || { echo "working tree is dirty — commit first"; exit 1; }

rm -rf "$WORK"; mkdir -p "$WORK"
git archive HEAD | tar -x -C "$WORK"

for path in "${EXCLUDE[@]}"; do
  rm -rf "${WORK:?}/${path}"
done

# The README points at the engineering guide, which is not in the mirror. A
# dead reference in the first file anybody reads is worse than no reference.
python3 - "$WORK/README.md" <<'PY'
import pathlib, re, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text()
s = re.sub(
    r"`CLAUDE\.md` is the engineering guide.*?first\nchange\.\n",
    "The conventions above are the ones worth knowing before a first change.\n",
    s, flags=re.S)
p.write_text(s)
PY

cd "$WORK"
git init -q -b main
git config user.name  "ammar-hassoun"
git config user.email "ammar-hassoun@users.noreply.github.com"
git add -A

for path in "${EXCLUDE[@]}"; do
  if git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
    echo "REFUSING: $path is still staged"; exit 1
  fi
done
if git grep -qIl "CLAUDE\.md" -- README.md 2>/dev/null; then
  echo "REFUSING: README.md still references CLAUDE.md"; exit 1
fi

VERSION="$(cat VERSION)"
git -c commit.gpgsign=false commit -q -m "DevOps EnvMap ${VERSION}

A self-hosted control plane for clusters, GitOps configuration, certificates,
pipelines, inventory and spend. Install it into your own cluster with one Helm
command; everything environmental is configuration, stored in your own
database. No licence key, no account, no telemetry.

Published under Apache-2.0. The mirror carries no history: it is rebuilt as a
single commit from a private repository developed against a live estate."

git remote add origin "$PUBLIC_REMOTE"
git -c credential.helper= -c credential.helper='!gh auth git-credential' \
    push --force -q origin main

echo "published ${VERSION}: $(git ls-files | wc -l | tr -d ' ') files, one commit"
