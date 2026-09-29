#!/usr/bin/env bash
# Recreate the public mirror from scratch: repository, settings, and a single
# commit of the current HEAD minus everything scripts/sync-public.sh excludes.
#
# Used after deleting the mirror — deleting is the only way to make an object
# that was force-pushed away unreachable, because GitHub keeps orphaned commits
# fetchable by SHA.
set -euo pipefail
REPO="ammar-hassoun/envmap"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if gh api "repos/$REPO" >/dev/null 2>&1; then
  echo "$REPO already exists — delete it first, or just run sync-public.sh"; exit 1
fi

gh repo create "$REPO" --public --description \
  "Self-hosted DevOps control plane: clusters, GitOps config, certificates, pipelines, inventory and spend — installed into your own cluster with one Helm command."

gh repo edit "$REPO" \
  --add-topic kubernetes --add-topic gitops --add-topic devops --add-topic helm \
  --add-topic self-hosted --add-topic argocd --add-topic sre --add-topic fastapi \
  --add-topic certificate-management --add-topic platform-engineering \
  --enable-issues --enable-wiki=false

"$ROOT/scripts/sync-public.sh"

gh api "repos/$REPO" --jq '"created: \(.html_url)  licence \(.license.spdx_id // "detecting…")  topics \(.topics|length)"'
