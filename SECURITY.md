# Security

DevOps EnvMap holds kubeconfigs, git tokens, sealing certificates and session
credentials wherever it is installed. A weakness in it is a weakness in every
estate that runs it, so reports are taken seriously and answered quickly.

## Reporting a vulnerability

**Report it privately.** On this repository open **Security → Report a
vulnerability**, or go straight to
<https://github.com/ammar-hassoun/envmap/security/advisories/new>. Only the
maintainer can read what you send. Please do not open a public issue or a
discussion for anything exploitable.

Say what you found, the version, and how to reproduce it. A proof of concept
helps and is not required.

What happens next:

- The maintainer reads every report and answers it, normally within a few
  days.
- You are told whether it is confirmed and what the fix will be.
- A fix ships as a new release. The release notes credit you unless you ask
  not to be named.

## Supported versions

Fixes go into the newest release. There are no maintenance branches, so the
way to get a fix is to upgrade. Migrations only add, and the database is
copied before each version change.

## Checking what you run

Every release image is signed without a stored key, by the release workflow.
Verify it before you trust it:

```bash
cosign verify ghcr.io/ammar-hassoun/devops-portal:latest \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/ammar-hassoun/devops-envmap/.github/workflows/release.yml@refs/heads/main
```

To run exactly the bytes you verified, pin `image.digest` in the Helm values.
A tampered image fails verification, and a pinned digest will not resolve to
it.

## What the image does to keep itself intact

- **It runs as a non-root user** (uid 10001) that owns nothing but its data
  volume.
- **The root filesystem is read-only** in the chart and in the Compose file.
  Nothing outside `/data`, `/tmp` and the user's home is writable, so the code
  cannot be edited in a running container.
- **All capabilities are dropped** and privilege escalation is off. The chart
  also sets the `RuntimeDefault` seccomp profile.
- **The application ships as bytecode with the sources removed.** That stops
  the code being edited in place. It is not secrecy: the source is in this
  repository.

## What the portal holds, and what follows from it

Its data directory contains git tokens, kubeconfigs, sealing certificates,
password hashes and TOTP secrets. Therefore:

- it refuses to bind a non-loopback address unless `PORTAL_ALLOW_NETWORK=1` is
  set deliberately (the chart and the Compose file set it, because a container
  address is not loopback);
- stored credentials are sealed in the database under `PORTAL_SECRET_KEY`;
- enrolling an authenticator app is mandatory, and there is no way in without
  one;
- every write, every cluster-changing command and every refusal is written to a
  hash-chained audit log with who did it;
- clusters are **read-only** until somebody allows management for that one
  cluster, and a cluster that serves production also asks for its name to be
  typed before anything that changes it;
- the kubectl console runs no shell: no pipes, no redirects, no `exec`, no
  `port-forward`, and no flag that could point it at another cluster.

Put it behind TLS, on an internal network, before anybody signs in. An
authenticating proxy in front of it as well is cheap defence in depth.

The full description is the
[security model](https://envmap.tech/docs/reference/security-model/) in the
docs.
