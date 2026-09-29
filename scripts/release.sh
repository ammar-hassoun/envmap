#!/usr/bin/env bash
#
# One version, everywhere.
#
# The VERSION file is the only place a release number is written by hand. This
# script copies it into the chart (version and appVersion) and into the image
# tag, so "which build is this?" has exactly one answer — the /healthz endpoint,
# the Deployment settings page, the chart and the tag all agree.
#
#   scripts/release.sh                 # stamp the chart from ./VERSION, build, verify
#   scripts/release.sh 0.2.0           # set ./VERSION first, then the same
#   PUSH=1 scripts/release.sh          # also push the image and package the chart
#
#
# Nothing is pushed unless PUSH=1 is set. Nothing is tagged in git: tagging is a
# decision, and CI does it from the tag you create yourself.
set -euo pipefail
cd "$(dirname "$0")/.."

REGISTRY="${REGISTRY:-ghcr.io}"
REPO="${REPO:-}"                       # e.g. ghcr-owner/config-portal
CHART="deploy/helm/config-portal"

if [[ $# -ge 1 ]]; then
  printf '%s\n' "$1" > VERSION
fi
VERSION="$(tr -d '[:space:]' < VERSION)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] || {
  echo "VERSION must be semver, got: '$VERSION'" >&2; exit 1; }

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

say "version $VERSION"

# ── stamp the chart ────────────────────────────────────────────
# sed in place, portably: BSD and GNU sed disagree about -i.
stamp() {
  local file="$1" key="$2" value="$3"
  local tmp; tmp="$(mktemp)"
  sed -E "s|^${key}:.*|${key}: ${value}|" "$file" > "$tmp" && mv "$tmp" "$file"
}
stamp "$CHART/Chart.yaml" version "$VERSION"
stamp "$CHART/Chart.yaml" appVersion "\"$VERSION\""
grep -E '^(version|appVersion):' "$CHART/Chart.yaml" | sed 's/^/    /'

# The chart's default image tag follows too, so `helm install` with no overrides
# installs the matching image rather than whatever "latest" happens to be.
tmp="$(mktemp)"
sed -E "s|^(  tag: ).*|\1\"$VERSION\"|" "$CHART/values.yaml" > "$tmp" && mv "$tmp" "$CHART/values.yaml"

say "helm lint"
helm lint "$CHART" | sed 's/^/    /'

say "helm template (default values must render)"
helm template release-check "$CHART" > /dev/null && echo "    renders clean"

# ── the image ──────────────────────────────────────────────────
if [[ -z "$REPO" ]]; then
  say "REPO is unset — building a local tag only"
  IMAGE="config-portal:$VERSION"
else
  IMAGE="$REGISTRY/$REPO:$VERSION"
fi

# ── publishing, only when asked ────────────────────────────────
if [[ "${PUSH:-}" != "1" ]]; then
  say "done (set PUSH=1 with REPO=owner/name to publish)"
  exit 0
fi
[[ -n "$REPO" ]] || { echo "PUSH=1 needs REPO=owner/name" >&2; exit 1; }

say "pushing $IMAGE"
docker push "$IMAGE" | tail -2 | sed 's/^/    /'

DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE" | cut -d@ -f2)"
say "digest $DIGEST"

if command -v cosign > /dev/null; then
  say "signing (keyless)"
  cosign sign --yes "$REGISTRY/$REPO@$DIGEST"
else
  say "cosign not installed — image is unsigned"
fi

say "packaging the chart"
helm package "$CHART" -d dist | sed 's/^/    /'

cat <<EOF

Installed with:
  helm install portal dist/config-portal-$VERSION.tgz \\
    --set image.repository=$REGISTRY/$REPO \\
    --set image.digest=$DIGEST
EOF
