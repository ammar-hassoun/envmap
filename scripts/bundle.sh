#!/usr/bin/env bash
#
# Everything a customer needs, in one file.
#
# Solves two problems at once:
#
#   * the registry is private, so `helm install` from the internet needs a GHCR
#     pull secret the customer has to be given and then rotate;
#   * some sites will not pull from the internet at all, and no amount of
#     documentation changes that.
#
# Both go away if the image and the chart travel as files. This produces one
# tarball holding the image, the chart, an install script and a README, so the
# customer needs no registry credentials, no chart repository and no network.
#
#   scripts/bundle.sh                      # bundle ./VERSION
#   scripts/bundle.sh 0.2.0                # bundle a specific version
#   REPO=owner/name scripts/bundle.sh      # pull that image rather than a local one
#
# The image is exported with `docker save`, so whatever is loaded is bit for
# bit what was tested — there is no tag to be re-pointed at something else
# between here and there.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-$(tr -d '[:space:]' < VERSION)}"
REGISTRY="${REGISTRY:-ghcr.io}"
REPO="${REPO:-}"
CHART="deploy/helm/config-portal"
OUT="dist/config-portal-$VERSION-offline"

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

IMAGE="config-portal:$VERSION"
[[ -n "$REPO" ]] && IMAGE="$REGISTRY/$REPO:$VERSION"

say "checking $IMAGE is here"
if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
  [[ -n "$REPO" ]] || { echo "no local $IMAGE — build it first, or set REPO" >&2; exit 1; }
  docker pull "$IMAGE"
fi

rm -rf "$OUT"; mkdir -p "$OUT"

say "saving the image (this is the slow part)"
docker save "$IMAGE" | gzip -9 > "$OUT/image.tar.gz"

say "packaging the chart"
helm package "$CHART" -d "$OUT" > /dev/null
mv "$OUT"/config-portal-*.tgz "$OUT/chart.tgz"

cat > "$OUT/install.sh" <<'INNER'
#!/usr/bin/env bash
# Load the image and install or upgrade the portal. No network needed.
#
#   ./install.sh <namespace> [release]
#
set -euo pipefail
cd "$(dirname "$0")"
NS="${1:-portal}"
RELEASE="${2:-portal}"
IMAGE="$(cat image.txt)"

echo "==> loading the image"
# containerd (k3s, RKE2) and Docker keep images in different places, so try
# the tools in the order most clusters have them.
if command -v ctr > /dev/null; then
  gunzip -c image.tar.gz | ctr -n k8s.io images import -
elif command -v nerdctl > /dev/null; then
  gunzip -c image.tar.gz | nerdctl load
else
  gunzip -c image.tar.gz | docker load
fi

echo "==> installing $RELEASE into $NS"
# imagePullPolicy=Never: the image is already on the node and there is no
# registry to fall back to, so a pull attempt would only produce a confusing
# ImagePullBackOff instead of a clear failure.
helm upgrade --install "$RELEASE" chart.tgz \
  --namespace "$NS" --create-namespace \
  --set image.repository="${IMAGE%:*}" \
  --set image.tag="${IMAGE##*:}" \
  --set image.pullPolicy=Never \
  "${@:3}"

echo
echo "Done. Watch it start with:"
echo "  kubectl -n $NS get pods -w"
INNER
chmod +x "$OUT/install.sh"
printf '%s\n' "$IMAGE" > "$OUT/image.txt"

cat > "$OUT/README.md" <<INNER
# Config Portal $VERSION — offline bundle

No registry account and no internet needed. Everything is in this directory.

## Install or upgrade

    ./install.sh <namespace> [release-name]

On a multi-node cluster the image has to be loaded on **every node that might
run the pod**, or pin it to one node. The simplest way is to copy this bundle
to each node and run the load step there.

## Upgrading

Exactly the same command with a newer bundle. Your data is on a
PersistentVolumeClaim and your configuration is in the portal's database, so
an upgrade never overwrites either — and the portal copies its database
before a new version applies any change to it.

## What is inside

| File | |
|---|---|
| \`image.tar.gz\` | the container image, exactly as tested |
| \`chart.tgz\` | the Helm chart, version $VERSION |
| \`install.sh\` | loads the image and runs helm upgrade --install |
| \`image.txt\` | the image reference the chart is pointed at |

## Verifying it before you trust it

    sha256sum -c SHA256SUMS
INNER

( cd "$OUT" && shasum -a 256 image.tar.gz chart.tgz install.sh > SHA256SUMS )

say "compressing"
tar -C dist -czf "$OUT.tar.gz" "$(basename "$OUT")"
rm -rf "$OUT"

say "done"
ls -lh "$OUT.tar.gz" | awk '{print "    " $9 "  " $5}'
cat <<EOF

Send that one file. On the customer's side:

    tar xzf $(basename "$OUT.tar.gz")
    cd $(basename "$OUT")
    ./install.sh portal
EOF
