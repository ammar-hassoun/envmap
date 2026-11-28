# Roadmap

What is planned for DevOps EnvMap, in the order it is likely to arrive. This is
a statement of direction, not a promise of dates. To change the order, say what
you need in [Discussions](https://github.com/ammar-hassoun/envmap/discussions):
requests from people who run EnvMap move things up.

## Next

- **Generic single sign-on.** OIDC, so Keycloak, Authentik, Okta and Google
  work beside Microsoft Entra ID.
- **EnvMap Move out of preview.** Moving a running Linux VM between Proxmox VE
  and ESXi is a preview today. Next are runs on more real hosts and moving a
  VM that is powered off.
- **Recorded web sessions that reach more than one host**, for applications
  whose API or sign-in lives on a second name.
- **An easier first hour.** A live demo, a shorter first run, and a starting
  point for people who have no Kubernetes cluster.

## Later

- **Privileged Access:** access requests with approval, command filtering,
  automatic credential rotation and break-glass access.
- **An external database** as an option, so an installation can survive the
  loss of a node.
- **Writing where EnvMap only reads today**, where it is safe: re-running a
  pipeline, syncing a Flux application.
- **More languages** for the interface and the docs.

## Not planned

- **Replacing the tools EnvMap reads.** It is not a CI system, a metrics
  store or a GitOps controller, and it will keep linking back to them.
- **A hosted service that holds your credentials.** EnvMap runs where you run
  it.
- **Telemetry.** An installation sends nothing to anyone you did not
  configure.

## Done lately

Every release is listed, with its notes, on the
[releases page](https://github.com/ammar-hassoun/envmap/releases).
