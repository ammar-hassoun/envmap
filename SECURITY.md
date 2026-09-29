# Security, and what "protecting the code" can and cannot mean

## What the image does to keep itself intact

* **The application ships as bytecode.** `compileall -b` then the `.py` files are
  deleted, so `/app/app` contains only `.pyc`.
* **It runs as a non-root user** (uid 10001) that owns nothing but its data
  volume.
* **The root filesystem is read-only** in the chart's `securityContext`. Nothing
  outside `/data`, `/tmp` and the pod's `$HOME` is writable, so the code cannot
  be edited in a running container — an `exec` into the pod cannot patch a
  handler, and neither can a compromised dependency.
* **All capabilities are dropped**, privilege escalation is off, and the seccomp
  profile is `RuntimeDefault`.
* **Images can be signed.** `scripts/release.sh` signs with cosign when it is
  installed, and the chart accepts `image.digest` so a deployment can pin exactly
  the bytes it reviewed.

## What none of that achieves

**Bytecode is not secrecy.** Anyone holding the image can extract the `.pyc`
files and decompile them; the result is readable Python with the comments
stripped. Treat the shipped image as readable by whoever can pull it, because it
is.

So the only real control over the source is **distribution**:

| Concern | The control that actually works |
|---|---|
| People reading the code | Keep the repository private and the registry private. A private GHCR package needs a pull secret, so nobody installs the chart without credentials you issued. |
| People modifying a running instance | Read-only root filesystem, non-root user, no shell needed at runtime — already in the chart. |
| People modifying the *image* and passing it off as yours | Sign it (cosign) and pin `image.digest`. A tampered image fails verification and a pinned digest will not resolve to it. |
| People running an old, vulnerable build | One `VERSION` file drives the image tag, the chart's `appVersion` and what the UI reports, so "which build is this?" always has an answer. |

If the code must stay unreadable by the people running it, the honest answer is
not to give them the image: run the portal yourself and give them access to the
instance, not to the artefact. Obfuscation buys minutes against someone
motivated, and costs you debuggability forever.

## What the portal holds, and what follows from it

Its data directory contains git tokens, kubeconfigs, sealing certificates,
password hashes and TOTP secrets. Therefore:

* it refuses to bind a non-loopback address unless `PORTAL_ALLOW_NETWORK=1` is
  set deliberately (the chart sets it, since a Service address is non-loopback)
* accounts are local, and enrolling an authenticator app is mandatory — there is
  no way in without one
* every write, every cluster-changing command and every refusal is written to an
  audit log with who did it
* clusters are **read-only** until someone ticks "allow management" for that
  specific cluster, and a cluster mapped to a production environment additionally
  requires its name to be typed before anything that changes it
* the kubectl console runs no shell: no pipes, no redirects, no `exec`, no
  `port-forward`, and no flag that could re-point it at another cluster

Put it behind an authenticating proxy on an internal network anyway. Defence in
depth is cheaper than an incident.

## Reporting something

Open a private security advisory on the repository, or contact the maintainer
directly. Please do not open a public issue for anything exploitable.
