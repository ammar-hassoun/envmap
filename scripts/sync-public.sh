#!/usr/bin/env bash
# Publish this repository's HEAD to the PUBLIC mirror, as ONE COMMIT ON TOP OF
# the mirror's history, and publish a GitHub Release there for the version.
#
#   scripts/sync-public.sh [--dry-run] [--rebuild] ["release notes"]
#
# Two repositories hold one product. This one is private and keeps the full
# development history; github.com/ammar-hassoun/envmap is public and gets one
# commit for each release, so a visitor can see what each release changed and
# that the project is alive.
#
# IT USED TO KEEP NO HISTORY AT ALL: the mirror was rebuilt as a single commit
# every time, so nothing that was ever excluded could be recovered from an
# older revision. That protection is gone on purpose (a one-commit repository
# with no releases reads as a code drop, and nobody trusts a code drop with
# their kubeconfigs), so two things replace it:
#
#   --dry-run   stops before anything is pushed and prints the folder that
#               would be published. Scan THAT folder (gitleaks, and a grep for
#               every private name) before a real run. What is published once
#               now stays in the mirror's history.
#   --rebuild   the old behaviour: replace the mirror's whole history with one
#               commit. It is the way out if something that should not have
#               been published ever is. It needs a force push, and the tags
#               and releases of older versions then point at commits that no
#               longer exist on main, so delete those by hand afterwards.
#
# THE EXCLUSION LIST IS THE POINT. A file kept out by hand is a file that gets
# published the first time somebody syncs in a hurry, so it lives here and the
# script is the only supported way to push the mirror.
set -euo pipefail

PUBLIC_REPO="ammar-hassoun/envmap"
PUBLIC_REMOTE="https://github.com/${PUBLIC_REPO}.git"
WORK="${TMPDIR:-/tmp}/envmap-public-sync"

DRY=0; REBUILD=0; NOTES=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    --rebuild) REBUILD=1 ;;
    --*) echo "unknown option: $arg"; exit 2 ;;
    *) NOTES="$arg" ;;
  esac
done

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
#   .github/workflows/release.yml
#                      it runs on any v* tag and publishes to the product's
#                      own image path. The mirror now gets a tag for each
#                      release, so a copy of this workflow there would build
#                      and try to publish the image a second time, from the
#                      mirror. Releases are cut here and nowhere else.
EXCLUDE=(CLAUDE.md .claude security .github/workflows/release.yml)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

[ -z "$(git status --porcelain)" ] || { echo "working tree is dirty — commit first"; exit 1; }
VERSION="$(tr -d '[:space:]' < VERSION)"
SOURCE_DATE="$(git log -1 --format=%cI)"

git_public() {
  git -c credential.helper= -c credential.helper='!gh auth git-credential' "$@"
}

rm -rf "$WORK"; mkdir -p "$WORK"
if [ "$REBUILD" = 1 ]; then
  git -C "$WORK" init -q -b main
  git -C "$WORK" remote add origin "$PUBLIC_REMOTE"
else
  git_public clone -q "$PUBLIC_REMOTE" "$WORK"
  if git -C "$WORK" rev-parse -q --verify "refs/tags/v${VERSION}" >/dev/null; then
    echo "REFUSING: the mirror already has v${VERSION}"; exit 1
  fi
  # the tree is replaced whole, so a file deleted here is deleted there
  git -C "$WORK" rm -rqf --ignore-unmatch . >/dev/null
  git -C "$WORK" clean -qfdx
fi

git archive HEAD | tar -x -C "$WORK"

for path in "${EXCLUDE[@]}"; do
  rm -rf "${WORK:?}/${path}"
done

# The reference points at the engineering guide, which is not in the mirror. A
# dead reference in a file anybody reads is worse than no reference.
python3 - "$WORK/README.md" "$WORK/docs/REFERENCE.md" <<'PY'
import pathlib, re, sys
for name in sys.argv[1:]:
    p = pathlib.Path(name)
    if not p.exists():
        continue
    s = p.read_text()
    s = re.sub(
        r"`CLAUDE\.md` is the engineering guide.*?first\nchange\.\n",
        "The conventions above are the ones worth knowing before a first change.\n",
        s, flags=re.S)
    p.write_text(s)
PY

cd "$WORK"
git config user.name  "ammar-hassoun"
git config user.email "ammar-hassoun@users.noreply.github.com"
git add -A

for path in "${EXCLUDE[@]}"; do
  if [ -n "$(git ls-files -- "$path")" ]; then
    echo "REFUSING: $path is still staged"; exit 1
  fi
done
if git grep -qIl "CLAUDE\.md" -- README.md docs/REFERENCE.md 2>/dev/null; then
  echo "REFUSING: README.md or docs/REFERENCE.md still references CLAUDE.md"; exit 1
fi
if git diff --cached --quiet; then
  echo "nothing to publish: the mirror already matches ${VERSION}"; exit 0
fi

# The commit carries the date of the commit it was made from, so the mirror's
# history reads in the order the releases happened, whenever it was synced.
GIT_AUTHOR_DATE="$SOURCE_DATE" GIT_COMMITTER_DATE="$SOURCE_DATE" \
  git -c commit.gpgsign=false commit -q -m "DevOps EnvMap ${VERSION}" \
      -m "${NOTES:-Release ${VERSION}.}"

FILES="$(git ls-files | wc -l | tr -d ' ')"
if [ "$DRY" = 1 ]; then
  echo "dry run: ${VERSION}, ${FILES} files, nothing pushed"
  echo "scan this folder before a real run: $WORK"
  git show --stat --format='%h %s' HEAD | tail -n 25
  exit 0
fi

if [ "$REBUILD" = 1 ]; then
  git_public push --force -q origin main
else
  git_public push -q origin main
fi

# The release is created on the commit just pushed, which carries no release
# workflow (see EXCLUDE), so the tag it makes builds nothing on the mirror.
BODY="${NOTES:-Release ${VERSION}.}

\`\`\`bash
helm upgrade --install envmap oci://ghcr.io/ammar-hassoun/devops-portal-charts/config-portal \\
  --version ${VERSION} --namespace envmap --create-namespace
\`\`\`

Image: \`ghcr.io/ammar-hassoun/devops-portal:${VERSION}\`, for linux/amd64 and linux/arm64, signed with cosign.
Docs: https://envmap.tech/docs/"
gh release create "v${VERSION}" --repo "$PUBLIC_REPO" --target "$(git rev-parse HEAD)" \
   --title "EnvMap ${VERSION}" --notes "$BODY"

echo "published ${VERSION}: ${FILES} files, one commit, release v${VERSION}"
