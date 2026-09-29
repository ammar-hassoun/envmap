# The portal, its three tools, and nothing else.
#
# Two things this Dockerfile is deliberate about:
#
#   * it carries kubectl, kubeseal, OpenTofu and git, pinned. The portal checks
#     for them at startup and refuses to run without kubectl and git, so an image
#     built without them fails immediately and says why rather than failing per
#     page.
#
#   * the Terraform engine ships as OPENTOFU, not HashiCorp Terraform, and that
#     is a licence decision rather than a preference. Terraform has been BUSL-1.1
#     since v1.6, and this image is redistributed to customers who run it
#     themselves — shipping a BUSL binary inside a commercial product is a
#     question nobody wants to answer later. OpenTofu is MPL-2.0, redistributable,
#     and a drop-in: `terraform.py` already resolves PORTAL_TERRAFORM, then
#     `terraform`, then `tofu`, so an installation that would rather use its own
#     Terraform still can by putting it on PATH or naming it.
#
#   * the application ships as bytecode with the sources removed, runs as a
#     non-root user, and needs no writable filesystem except its data volume.
#     That stops the code being edited in a running container. It is not secrecy
#     — bytecode can be decompiled by anyone who has the image — so the real
#     control is who can pull it. See SECURITY.md.

# ── tools, fetched and verified in a throwaway stage ────────────
FROM debian:12-slim AS tools
ARG TARGETARCH=amd64
ARG KUBECTL_VERSION=v1.34.1
ARG KUBESEAL_VERSION=0.27.3
ARG TOFU_VERSION=1.12.6
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /out
RUN curl -fsSL -o kubectl \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
 && curl -fsSL -o kubectl.sha256 \
      "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl.sha256" \
 && echo "$(cat kubectl.sha256)  kubectl" | sha256sum -c - \
 && chmod +x kubectl && rm kubectl.sha256
RUN curl -fsSL -o kubeseal.tar.gz \
      "https://github.com/bitnami-labs/sealed-secrets/releases/download/v${KUBESEAL_VERSION}/kubeseal-${KUBESEAL_VERSION}-linux-${TARGETARCH}.tar.gz" \
 && tar -xzf kubeseal.tar.gz kubeseal && chmod +x kubeseal && rm kubeseal.tar.gz
# Checksum-verified against the release's own SHA256SUMS, the way kubectl is:
# this binary is handed provider credentials and told to change infrastructure,
# so "it downloaded without erroring" is not the bar.
RUN curl -fsSL -o tofu.tar.gz \
      "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_${TARGETARCH}.tar.gz" \
 && curl -fsSL -o tofu.sums \
      "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_SHA256SUMS" \
 && grep " tofu_${TOFU_VERSION}_linux_${TARGETARCH}.tar.gz$" tofu.sums \
      | sed "s/tofu_${TOFU_VERSION}_linux_${TARGETARCH}.tar.gz/tofu.tar.gz/" \
      | sha256sum -c - \
 && tar -xzf tofu.tar.gz tofu LICENSE && chmod +x tofu \
 && mv LICENSE opentofu-LICENSE.txt \
 && rm tofu.tar.gz tofu.sums

# ── python dependencies ────────────────────────────────────────
FROM python:3.13-slim AS deps
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /venv \
 && /venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# ── the image that ships ───────────────────────────────────────
FROM python:3.13-slim AS runtime
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="config-portal" \
      org.opencontainers.image.description="Self-hosted DevOps control plane: GitOps config, clusters, pipelines, security, logs" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

# git for the repositories, ca-certificates so HTTPS remotes verify, and
# openssh-client because the portal offers ssh as a repository protocol and git
# shells out to `ssh` to use it. Without it an ssh remote fails with
# "ssh: not found" reported as "Could not read from remote repository", which
# reads like a rejected deploy key and sends you looking at the wrong thing.
# The root filesystem is read-only at runtime, so this cannot be added later.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 10001 --create-home --home-dir /home/portal --shell /usr/sbin/nologin portal

COPY --from=tools /out/kubectl /out/kubeseal /out/tofu /usr/local/bin/
# MPL-2.0 asks that the licence travel with the binary, the same discipline the
# vendored noVNC and guacamole-common-js already follow in static/.
COPY --from=tools /out/opentofu-LICENSE.txt /usr/local/share/licenses/
COPY --from=deps /venv /venv

WORKDIR /app
COPY app/ /app/app/
COPY templates/ /app/templates/
# The UI's own CSS is still inlined in the base template. What lives here is the
# terminal emulator (xterm.js, MIT, vendored — see static/xterm.LICENSE.txt),
# which is far too large to inline into every page and is loaded only by the pod
# shell. The directory is tracked and never empty, so this COPY is safe; it was
# not before, and a COPY of a directory git does not track fails only in CI.
COPY static/ /app/static/
COPY VERSION /app/VERSION

# Compile to bytecode and drop the sources. Anyone with the image can still
# decompile it — this makes the code not-editable-in-place, not secret.
RUN /venv/bin/python -m compileall -q -b /app/app \
 && find /app/app -name "*.py" -delete \
 && find /app -name "__pycache__" -type d -prune -exec rm -rf {} + \
 && mkdir -p /data && chown -R portal:portal /data /app

# PORTAL_TOOL_PATH below includes /venv/bin, and that is not a copy-paste of
# PATH: pip installs ansible-playbook beside the interpreter, so a tool path
# without the venv in it finds kubectl and git and reports ansible as "not
# installed" — in the image only, where nobody is watching a terminal.
ENV PATH="/venv/bin:/usr/local/bin:/usr/bin:/bin" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORTAL_DATA_DIR=/data \
    PORTAL_PORT=8471 \
    PORTAL_TOOL_PATH="/venv/bin:/usr/local/bin:/usr/bin:/bin" \
    FORWARDED_ALLOW_IPS="*"

# WHY FORWARDED_ALLOW_IPS IS SET, and why "*" is the right value HERE.
#
# uvicorn already parses X-Forwarded-Proto/Host (proxy_headers defaults to
# True) but only from a peer on its trust list, and that list defaults to
# 127.0.0.1 — a default meant for a process behind a local nginx, not for a
# container behind an ingress. So every request from Traefik had its headers
# discarded, and the app concluded it was reached over http at its own hostname
# even while the browser was on https.
#
# That is invisible until something DERIVES a URL from the request, and then it
# is badly wrong: passkeys refused to work at all (WebAuthn is a secure-context
# API, so `readiness()` correctly reported "this portal is reached over http"),
# the SSO redirect URI came out with the wrong scheme — which is why that
# feature has a manual override — and invitation and reset links would be built
# as http.
#
# "*" means "trust whatever peer connects", and inside a cluster that peer is
# the Service. It is the normal setting for a containerised app behind an
# ingress. The honest limit: anybody who can reach the pod DIRECTLY, bypassing
# the ingress, can then claim any scheme and host. What that buys them is a
# derived origin — and for passkeys the browser still enforces the real one, so
# a spoofed RP ID produces a credential nobody can use. An installation that
# wants it narrower overrides this env with the ingress's own range; it is
# deliberately an environment variable rather than a chart value, because it is
# a property of how the pod is fronted rather than something to configure.

USER 10001
EXPOSE 8471
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/venv/bin/python", "-c", "import urllib.request,os;\
urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('PORTAL_PORT','8471')}/healthz\").read()"]
# THE WEBSOCKET KEEPALIVE IS RELAXED, and that is a fix rather than a default
# nobody thought about. uvicorn pings a websocket every 20s and CLOSES it after
# 20s without a pong — so a proxy that does not forward ping/pong frames kills a
# perfectly healthy connection at about forty seconds. Reported from an install
# behind a cloud load balancer as `keepalive ping timeout` on a blank pane:
# exactly the window a browser seat needs to be scheduled, pulled and started,
# during which the socket carries nothing in the client-to-server direction. An
# interactive SSH terminal never showed it because it is never quiet that long.
#
# A long timeout is safe here because nothing depends on this ping to notice a
# dead client: a send to a closed socket fails on its own, the PAM relay has its
# own idle and maximum-duration guards, and the console sends the protocol's own
# `nop` every three seconds while it waits.
ENTRYPOINT ["/venv/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8471", \
            "--ws-ping-interval", "30", "--ws-ping-timeout", "300"]
