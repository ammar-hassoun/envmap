# DevOps EnvMap

**A self-hosted DevOps control plane.** DevOps EnvMap puts a whole estate on
one screen: Kubernetes clusters, the GitOps configuration behind them, Argo CD
and Flux, pipelines, monitoring and Grafana dashboards, logs, security scanners,
certificates, clouds, hypervisors, server hardware, databases, VPNs, the
server inventory and IT spend. It also lets a team act on what it sees. You can
edit and seal values files and push them to git, sync or roll back
applications, request certificates, run Ansible and Terraform, provision
virtual machines and Talos clusters, and open recorded privileged sessions.

It runs in your own cluster and installs with one Helm command. There is no
licence key, no account to register anywhere, and no telemetry. It starts with
an empty database, asks you to create the first administrator, and waits for
you to connect something. Your projects, clusters, repositories and credentials
are configuration entered in the UI and kept in your own database, and nothing
about any particular company or estate is built into the code.

Apache-2.0 · Python and FastAPI · one container image · `linux/amd64` and
`linux/arm64` · signed with cosign

---

## Contents

- [Principles](#principles)
- [Quick start](#quick-start)
- [Installing with Helm](#installing-with-helm)
- [Running it locally](#running-it-locally)
- [First run](#first-run)
- [What DevOps EnvMap can do](#what-devops-envmap-can-do)
  - [Overview, search and navigation](#overview-search-and-navigation)
  - [Kubernetes clusters](#kubernetes-clusters)
  - [GitOps configuration: values files](#gitops-configuration-values-files)
  - [GitOps controllers: Argo CD and Flux](#gitops-controllers-argo-cd-and-flux)
  - [Pipelines](#pipelines)
  - [Workflow engines](#workflow-engines)
  - [Security scanning](#security-scanning)
  - [Logs](#logs)
  - [Monitoring, alerts and Grafana dashboards](#monitoring-alerts-and-grafana-dashboards)
  - [Certificates](#certificates)
  - [Expiry radar](#expiry-radar)
  - [Timeline](#timeline)
  - [Edge and DNS](#edge-and-dns)
  - [Cloud accounts](#cloud-accounts)
  - [Server hardware](#server-hardware)
  - [Hypervisors](#hypervisors)
  - [Storage devices](#storage-devices)
  - [Databases](#databases)
  - [VPN portals](#vpn-portals)
  - [Server assets](#server-assets)
  - [IT spend](#it-spend)
  - [Ansible](#ansible)
  - [Terraform and infrastructure provisioning](#terraform-and-infrastructure-provisioning)
  - [Privileged Access (PAM)](#privileged-access-pam)
  - [The assistant](#the-assistant)
  - [AI clients over MCP](#ai-clients-over-mcp)
- [Sign-in, users, roles and audit](#sign-in-users-roles-and-audit)
- [Administration](#administration)
- [Security model](#security-model)
- [The data model](#the-data-model)
- [Where data lives](#where-data-lives)
- [Configuration reference](#configuration-reference)
- [Performance](#performance)
- [Extending it](#extending-it)
- [Development and releasing](#development-and-releasing)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [Licence](#licence)
- [Contributing](#contributing)

---

## Principles

**Read-only first.** Every integration starts read-only and so does every
cluster. A write is something an administrator switches on for one cluster and
grants to specific people. It is never a side effect of the credential you
pasted.

**Git is the write path for configuration.** Changing a values file produces a
commit authored by the signed-in person and pushed to your repository. Your
existing delivery tool, whether Argo CD, Flux or a pipeline, does the
deploying exactly as it does today.

**Nothing environmental is in the code.** Service names, key prefixes,
hostnames, index patterns and folder meanings are configuration. The product
can be rebranded, and the defaults are neutral.

**"None" and "could not ask" never look the same.** A scanner that did not
answer shows a dash, never a zero. A cluster that could not be read is an
error, never an empty list. A page that is still waiting on a slow system says
which one.

**Fast on a slow estate.** Pages render within a fixed deadline and fill in as
the slow sources answer, and caches are warmed before anybody asks. No page is
as slow as the slowest thing it reads.

---

## Quick start

```bash
git clone https://github.com/ammar-hassoun/envmap.git
helm install envmap ./envmap/deploy/helm/config-portal --namespace envmap --create-namespace
kubectl -n envmap port-forward svc/envmap-config-portal 8471:8471
```

Open <http://localhost:8471>, create the first administrator, enrol an
authenticator app, and add a cluster.

The container image `ghcr.io/ammar-hassoun/devops-portal` is public, so you
need no pull secret and no registry login. The chart is also published as an
OCI artifact with every release:

```bash
helm install envmap oci://ghcr.io/ammar-hassoun/devops-portal-charts/config-portal --namespace envmap --create-namespace
```

---

## Installing with Helm

### Put it behind TLS before anybody signs in

DevOps EnvMap holds kubeconfigs, git tokens and sealing keys. Passkeys will not
work over plain HTTP at all, because WebAuthn is a secure-context API, and the
sign-in page says so instead of failing quietly.

Save this as `values.yaml`:

```yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: envmap.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - hosts: [envmap.example.com]
      secretName: envmap-tls
portal:
  cookieSecure: true
  secretKey: "paste the output of: openssl rand -hex 32"
```

Then install:

```bash
helm upgrade --install envmap ./envmap/deploy/helm/config-portal -n envmap --create-namespace -f values.yaml
```

`portal.secretKey` encrypts every stored credential and keys the audit log's
hash chain. If you leave it empty, the portal generates a key file next to the
database. That still works, but a copied volume then holds both the data and
its key. Set the value, keep it stable, and back it up. A lost or rotated key
makes the stored credentials unreadable and the audit chain unverifiable.

`PORTAL_BASE_URL` (set through `portal.extraEnv`) is the address people reach
the portal at. Invitation and password-reset emails use it to build their
links, so it cannot be steered by a forged `Host` header.

### Values worth knowing

| Value | Default | What it does |
|---|---|---|
| `image.digest` | `""` | pins the deployment to exact reviewed bytes; wins over `image.tag` |
| `image.tag` | `""` | leave empty so the image follows the chart's `appVersion`. A pinned tag leaves the image behind on `helm upgrade`, and the pre-upgrade backup never runs |
| `persistence.enabled` / `size` / `storageClass` / `existingClaim` | `true` / `8Gi` / cluster default / none | the database, git checkouts, Terraform state and session recordings live on this volume |
| `portal.secretKey` | `""` | see above |
| `portal.cookieSecure` | `false` | set `true` whenever TLS is in front |
| `portal.sessionHours` | `8` | session lifetime |
| `portal.rootPath` | `""` | set when an ingress serves the portal under a path prefix |
| `portal.brand.name` / `org` / `short` | `""` | the product name, subtitle and authenticator issuer shown in the UI; empty means the default brand |
| `portal.extraEnv` / `extraEnvFrom` | `[]` | any `PORTAL_*` variable from the [configuration reference](#configuration-reference) |
| `resources` | requests `100m` / `256Mi`, limits `1` CPU / `1Gi` | raise the memory limit for a large estate. Tens of clusters and several integrations need 2Gi to 4Gi |
| `rbac.createReadOnly` | `false` | a cluster-wide read-only ClusterRole for the portal's own ServiceAccount, so it can read the cluster it runs in without a pasted kubeconfig |
| `rbac.selfUpdate` | `false` | adds an **Update to X** button on the About page. It creates a Role that may `get` and `patch` this release's own Deployment by name and nothing else. It does nothing on a digest-pinned install |
| `guacd.enabled` | `true` | the Apache Guacamole sidecar that carries and records RDP, VNC and recorded web sessions in Privileged Access |
| `ollama.enabled` | `false` | runs a local model (`llama3.2:3b` by default) beside the portal, so the assistant works without any external provider |
| `assistant.provider` / `url` / `model` | `""` | seeds the assistant's provider; it can also be set in the UI |
| `updateUrl` | `""` | where the About page looks for newer releases. Empty means no check and no network call |

### What the chart creates

| Object | Notes |
|---|---|
| `Deployment` | one replica, `Recreate` strategy. Runs as UID 10001 with a read-only root filesystem, all capabilities dropped and `RuntimeDefault` seccomp. `replicaCount > 1` works, and the chart adds pod affinity so the replicas share one node's volume |
| `PersistentVolumeClaim` | mounted at `/data` and annotated `helm.sh/resource-policy: keep`, so `helm uninstall` cannot take your configuration with it |
| `Secret` | the `PORTAL_*` settings, kept out of `kubectl describe` |
| `Service` | ClusterIP on port 8471 |
| `ServiceAccount` | the pod's identity |
| `Ingress` | only when `ingress.enabled=true` |
| `Role` / `RoleBinding` | only with `rbac.selfUpdate=true`, scoped to this release's Deployment by name |
| `ClusterRole` / `ClusterRoleBinding` | only with `rbac.createReadOnly=true` |
| `guacd` sidecar | on by default. A sidecar, not a separate Deployment, because it writes recordings to the same volume the portal serves them from |
| Ollama `Deployment`, `Service`, `PVC` | only with `ollama.enabled=true` |

Everything else, including projects, clusters, repositories, connections and
users, is entered in the running portal and stored on the volume. **A chart
upgrade never rewrites your configuration.**

### What it needs from a cluster

Nothing installed. You paste a kubeconfig per cluster and DevOps EnvMap reads
with it. A `view`-scoped ServiceAccount token covers every read-only page, and
it is what we recommend. Pod logs need `pods/log`, and certificate views need
`secrets` read. Grant these deliberately, because application logs often
contain personal data. Kubeconfigs that point at files on your own machine, or
that authenticate through an exec plugin, are refused at registration because
the portal runs somewhere else.

### Upgrading

```bash
git -C envmap pull
helm upgrade envmap ./envmap/deploy/helm/config-portal -n envmap -f values.yaml
```

- Before a new version touches the schema, the portal copies the database to
  `/data/backups/`. Migrations are additive and there is no down-migration, so
  that copy is what makes `helm rollback` safe.
- The About page shows the running version and, when `updateUrl` is set,
  whether a newer release exists. With `rbac.selfUpdate=true` it can update
  itself in one click.
- `VERSION` is the only hand-written version number. It drives the image tag,
  the chart's `version` and `appVersion`, `/healthz` and
  **Settings → Deployment**, so all of them agree by construction.

```bash
curl -s https://envmap.example.com/healthz
```

```json
{"status":"ok","version":"0.7.39"}
```

---

## Running it locally

| Needs | Why | Without it |
|---|---|---|
| Python 3.10 or newer (the image runs 3.13) | the application | will not start |
| `git` | clone, commit and push | will not start |
| `kubectl` | every cluster read | will not start |
| `kubeseal` | sealing secret values | sealing is unavailable, and Settings → Deployment says so |
| `ssh` / `sftp` | SSH git remotes, Ansible, SSH sessions and file transfer | HTTPS repositories still work |
| `terraform` or `tofu` | Terraform stacks and VM provisioning (the image ships OpenTofu) | those pages say the engine is missing |
| `guacd` | RDP, VNC and recorded web sessions | those targets say the gateway is not reachable; SSH is unaffected |

`kubectl` and `git` are checked at startup. If either is missing the portal
refuses to start, and the message names the binary and the `PATH` it searched.
Ansible is a Python dependency and installs with the rest.

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/uvicorn app.main:app --port 8471 --reload
```

Or bring up the portal together with a local model for the assistant,
reloading on every save:

```bash
scripts/dev.sh
```

`scripts/dev.sh status` and `scripts/dev.sh stop` manage it. The script uses a
native `ollama` if you have one (on Apple Silicon that runs on the GPU), then
Docker, then `--cluster CONTEXT` to borrow an Ollama already running in a
cluster. `--model`, `--no-ai` and `--port` adjust it, and it only ever stops
processes it started itself.

The portal **refuses to bind to a non-loopback address** unless
`PORTAL_ALLOW_NETWORK=1` is set, because the process holds git tokens,
kubeconfigs and sealing keys. The chart sets it for you, since a Service
address is not loopback.

---

## First run

1. The portal creates its data directory and sends you to `/bootstrap`.
2. **Create the first administrator.** The username is an email address, and
   the password needs at least 10 characters, mixed case and a digit.
3. **Enrol two-factor authentication.** Scan the QR code with any TOTP app.
   This is mandatory and cannot be skipped. You can add a passkey afterwards.
4. **Settings → Kubernetes clusters.** One form registers everything at once:
   the project, the cluster, its kubeconfig and context, a sealing certificate,
   the region and environment it serves, and the GitOps repository, branch,
   path and credentials behind that environment. Projects and regions can be
   created from inside the form's own dropdowns, so a half-filled form is never
   lost to a detour.
5. **Connect the rest** from Settings: pipelines, scanners, log platforms,
   monitoring, GitOps controllers, clouds and so on. Each connection has a
   **Test** button that proves it answers before you rely on it.

There is no default account and no default password.

---

## What DevOps EnvMap can do

Every page follows one shape. An **Overview** tab of headline tiles comes
first, and each tile links to exactly the rows it counts. Chart panels follow,
and then one tab per section. Tables sort when you click a column header. Every
destructive action asks you to type **Delete**, and production targets ask for
their own name. Every change is written to the audit log.

### Overview, search and navigation

- **Fleet overview.** Every cluster on one page, with node readiness, pod
  health, CPU and memory against real allocatable capacity, the busiest
  namespaces and the pods that need attention. Roll-ups sit beside it for
  pipelines, security findings, firing alerts, GitOps applications, workflow
  engines, hypervisors, databases, inventory, spend, repositories, recent
  activity and logs.
- **Your own layout.** The Overview is sixteen panels. Each person drags them
  into their own order and width, and the layout is stored per person.
- **Projects navigation.** Each project opens its regions and environments,
  and each environment shows its services, where they run, and their live pods
  and logs.
- **Global search.** Press `/` to search services, config keys, sealed-secret
  key names, environments and clusters.
- **Compare.** Pick a service and read its configuration across every
  environment side by side, with the differences highlighted. It is the fastest
  answer to "what is different about staging?".
- **Repositories.** Clone status, branch, HEAD, uncommitted changes, and
  whether the remote has moved ahead of the local checkout.
- **Themes and layout.** Dark and light themes, a collapsible sidebar, and
  themed dropdowns everywhere. Branding is configurable, so the product can
  carry your own name.

### Kubernetes clusters

**Clusters** lists every connected cluster with its live reachability and the
environments it serves. Two fleet-wide pages, **Nodes** and **Pods**, list
every node and every pod across every cluster at once.

Each cluster opens into thirteen tabs:

| Tab | What it shows |
|---|---|
| Overview | health, capacity, what needs attention |
| GitOps repo | the values files of every environment this cluster serves, opened in the values window |
| Diagram | an architecture diagram generated from the values files plus what is actually running |
| Nodes | readiness, capacity and usage, with cordon, uncordon and drain |
| Workloads | Deployments, StatefulSets, DaemonSets and CronJobs, with restart, scale and roll back |
| Pods | status, restarts, containers, live logs, describe, YAML and a terminal |
| Events | what needs attention, warnings grouped by cause, and recent events |
| Storage | volume claims, volumes and storage classes |
| Network | services, ingresses and the certificates they serve |
| CRDs | the custom resources installed |
| kubectl shell | a validated `kubectl` console for this cluster |
| Access | create ServiceAccounts bound to a role, mint their tokens and hand out a ready kubeconfig. It also lists what was handed out and revokes it |
| Scan | a security audit of the cluster that installs nothing in it |

The top bar adds a **kubectl** console, a **Troubleshoot** button and
**Provision a VM**. Troubleshoot starts a short-lived debugging pod with DNS,
`curl`, `nc`, `dig`, `traceroute` and `ss` on the cluster you choose, opens a
terminal in it, and deletes it on a timer (`PORTAL_NETSHOOT_IMAGE`,
`PORTAL_NETSHOOT_TTL`).

**Cluster management is opt-in, per cluster and per person.** A cluster stays
read-only until somebody ticks *allow management* on it, and even then every
action needs the Cluster management permission. The actions are a fixed list:

- rolling restart, scale and roll back
- delete a pod
- cordon, uncordon and drain
- ask Argo CD to sync
- edit and apply the manifest of an object that already exists
- a pod terminal
- install metrics-server for clusters with no usage figures (from a URL you
  can point at a mirror, and checked before anything is applied)

A cluster that serves a production environment also needs its name typed
before any of these run. Every action is audited, and so is every refusal.

### GitOps configuration: values files

This is where the product started: the Helm values files in your GitOps
repositories, edited safely and pushed as commits.

- **Environments are declared, not guessed.** Each environment carries its own
  complete binding: the repository URL, branch, path, protocol (HTTPS with a
  token, or SSH with a deploy key) and credentials. Environments that share a
  repository share one checkout.
- **A service is one values file.** By default that is any `*-values*.yaml`
  in the environment's folder (`-values.yaml`, `-values02.yaml`,
  `-values-eu.yaml`). A project can change which files count, or describe any
  repository layout (flat, service-first or nested) with a path pattern using
  `{env}` and `{svc}`.
- **The values window edits the file's text.** Comments survive, nothing is
  re-serialised, and a one-line change is a one-line diff. The file must parse
  before it is saved. Duplicate keys are reported and not refused, because
  Helm tolerates them (the last one wins) and real files have them.
- **Sealing a secret is a key and a value.** DevOps EnvMap reads the scope
  (`namespace` and `secretName`) off the file, seals the value with `kubeseal`
  using a certificate you paste or one fetched from the cluster's controller,
  and writes the blob where that scope is valid. The plaintext goes to
  `kubeseal` and nowhere else. The audit line records only the key's name.
- **Commit and push as yourself.** Review the diff, write a message and push.
  The commit is authored by the signed-in person, so `git log` names who
  changed what. You can push to a new branch instead of a protected one.
  Production pushes need an extra confirmation, and whether an environment
  counts as production follows its alias, not its folder name.
- **Add a whole new service** from an environment's page.
- **Naming conventions per project**, all optional and empty by default:
  services to hide (glob patterns), platform key prefixes shown separately
  from service config, display suffixes to strip, and display names for
  environment folders.

### GitOps controllers: Argo CD and Flux

**Argo CD, built to Argo's own layout** so that anybody who knows Argo CD can
work here without learning a new tool. Every call goes through the
connection's Argo CD account, so Argo's own RBAC is the authority.

- **The applications list.** It is a filter rail with live counts (name,
  project, sync status, health, sync policy) beside a grid of application
  tiles. The tiles carry project, labels, status, repository, target revision,
  path, destination, namespace and last sync.
- **The application page.** It opens with the same toolbar Argo CD has: App
  details, App diff, Sync, Sync status, History and rollback, Delete, Refresh
  (with Hard refresh and Dry run), and Terminate while an operation runs.
  Health, sync and last-sync cards carry the author and commit message behind
  the revision.
- **A live resource map** that animates what an action does. New pods pop in,
  terminating ones drain away, and each box says what Kubernetes says
  (`ContainerCreating`, `Running · 1/1`, `CrashLoopBackOff`). Boxes are colour
  coded by resource family, with a legend, and the arrows show which way the
  application is applied.
- **Per-resource actions** from a menu on every box: details, logs, live
  manifest, diff, restart, sync just this one, the controller's own resource
  actions (restart, suspend, promote), and delete. Actions are read from Argo
  CD, so custom ones appear too. A resource can also be edited live through
  Argo CD's API, or you can jump to its values file in git.
- **The whole-application review.** One read shows every difference between
  git and the cluster. Each row is marked *missing*, *extra* (the rows a prune
  would remove) or *changed*. Tick rows to run a selective sync.
- **Rollback** by history entry, **terminate** a running operation,
  **rendered-with** (Helm parameters, values files, inline values, Kustomize
  images, sync options), the application's own events, and a searchable
  resource list beside the map.

**Flux** has no API, so DevOps EnvMap reads its `Kustomization` and
`HelmRelease` objects through the cluster's own kubeconfig.

### Pipelines

**Jenkins, GitHub Actions, Bitbucket Pipelines and GitLab CI.** Build tables
per provider and connection show branch names, live stage progress, and build
logs read inside the portal. Jenkins folders and multibranch jobs are
supported, and the server's own views become tabs. Pipelines are read-only:
DevOps EnvMap never triggers or cancels a build.

| Provider | Needs |
|---|---|
| Jenkins | base URL, username, API token |
| GitHub Actions | `owner/repo` and a fine-grained token with Actions read |
| Bitbucket Pipelines | `workspace/repo`, plus a workspace or repository access token (leave the username blank), or a username and app password |
| GitLab CI | base URL, project, a token with `read_api` |

### Workflow engines

**Temporal and Apache Airflow.** See what is running and what has failed in
each namespace, and open a run to see its history. When a payment retry or a
nightly batch is stuck, the symptom reaches a support queue long before a
cluster metric, so these sit next to the clusters.

### Security scanning

**DefectDojo, Dependency-Track, Wazuh and SonarQube.**

- **DefectDojo is a full console.** It covers the finding lifecycle: open,
  closed, mitigated, risk accepted, false positives, out of scope, and all.
  Each has an exact count, and every number on a view comes from the same
  scope as the list it opens. A finding opens inside the portal as a readable
  document with its description, mitigation, impact, CVSS and EPSS, CVE, GHSA
  and CWE links, and notes.
- **Counts are exact**, taken from count queries rather than estimated from a
  sample. When a count cannot be fetched it shows as a dash, never as a zero.
- Each cluster's **Scan** tab adds a Kubernetes security audit that installs
  nothing.

### Logs

**Elasticsearch, OpenSearch and Grafana Loki**, searched from inside the
portal with level and time-window filters. Opening a connection shows the
shape of the window before you type anything:

- a volume histogram, with an errors-only strip on its own scale
- the fields that explain the traffic
- the repeating message shapes

Click any value to add it to the query. Breakdown fields are discovered from a
random sample of the data, never from a list of names. Field names are
detected from a real document (ECS, Fluent Bit or anything else), and you can
override them per connection. Live pod logs stream straight from the clusters
as well.

### Monitoring, alerts and Grafana dashboards

**Prometheus** (and anything that speaks its API: Thanos, Mimir, Cortex,
VictoriaMetrics), **Alertmanager**, **Grafana** and **Zabbix**.

- **One "firing now" list across every system and every cluster.** Each alert
  is colour coded by severity and shows its labels, annotations, source,
  cluster and how long it has been firing. Pending, silenced and inhibited
  alerts are left out, because they are not firing. The Overview tab adds
  tiles and charts by severity, system and cluster, plus scrape-target health.
- **Grafana dashboards drawn natively inside DevOps EnvMap.** There is no
  iframe, no anonymous access, and Grafana's token never leaves the server.
  The dashboard's own JSON is laid out the way Grafana lays it out: rows, the
  24-column grid, and collapsed rows that are not queried until opened. Its own
  queries run through Grafana's API.
  - **Variables:** query, custom, constant, interval, data source and text box.
    They resolve in dependency order, with multi-value and *All*.
  - **Time:** a time-range picker with quick ranges, plus auto-refresh.
  - **Panel types:** time series (with a hover tooltip), stat, gauge, bar
    gauge, table, pie chart and text (sanitised). Legacy singlestat and graph
    panels are converted.
  - **Formatting:** units, decimals, thresholds, value mappings, field
    overrides and transformations (merge, organize, filter by name, rename by
    regex, sort, limit), coloured the way Grafana colours them.
  - Any panel type not drawn yet links straight to Grafana.
- **Playlists and TV mode.**
  - **What rotates:** every dashboard, or one folder, tag or search.
  - **Timing:** you choose how long each dashboard stays up.
  - **TV mode:** full screen, with no chrome.
  - **Auto-scroll:** each dashboard scrolls to the bottom, holds there for a
    few seconds, then moves to the next.
  - **Speed:** auto, slow, medium, fast or very fast, fine-tuned with `−`/`+`.
  - **Controls:** scrolling or touching pauses it, and it respects reduced
    motion. Keys are space, ←/→, `−`/`+` and Esc.

### Certificates

- **A built-in ACME client (RFC 8555)** for Let's Encrypt, Let's Encrypt
  staging, or any other ACME CA. There is no certbot and no terminal.
- **DNS-01 validation.** The portal shows the TXT records to create, checks
  that they are visible (asking the zone's own nameservers when it can find
  them), and finishes the order by itself, even after the browser is closed.
- **Key types:** RSA 2048, 3072 or 4096 and ECDSA P-256 or P-384. You can also
  reuse an existing key.
- **Certificates signed by somebody else.** For a commercial CA, generate the
  private key and a CSR with a full subject here. The key is sealed and waits.
  When the certificate arrives, attach it: the portal proves it matches the key
  (and refuses a mismatch), puts the chain in order, and reports any names the
  CA changed.
- **Downloads:** the certificate, the chain, the key, or a **PKCS#12**. The
  `.p12` comes in a modern format (AES-256) or a legacy one (3DES and SHA-1)
  for Java 8. Downloading a key or a `.p12` is audited.
- **Renew** in one click. Every certificate also feeds the expiry radar.

### Expiry radar

Everything that runs out, on one clock, with its renewal story attached:

- **Certificates** issued in DevOps EnvMap, plus the TLS secrets found in every
  cluster. Each one says who renews it: cert-manager, CloudNativePG, another
  known operator, or *needs a person*. A certificate that claims a renewer but
  has passed its own renewal window is flagged as overdue.
- **Hardware warranties** from the server inventory.
- **Subscriptions and licences** from IT spend.
- **Invitations** that are about to lapse.

You can narrow the radar by project, cluster and region, with counts on every
option. **What breaks if I do not renew this?** walks one certificate's names
to the hosts an ingress answers for, then their routes and backend services,
then the environments on that cluster. It follows RFC 6125 wildcard rules and
matches in-cluster service names as well. A row can be set aside with a written
reason, so it stops counting, and it can be counted again later.

### Timeline

What changed, from every system at once, on one clock: commits, portal
actions, builds, deployments, cluster events, alerts, workflow runs, security
scans and certificates. This is the first question of every incident: what
changed just before it broke?

### Edge and DNS

**Cloudflare, Fastly, Bunny.net, NS1**, and anything else you want listed.
Zones and records can be exported to CSV. Cloudflare can also be acted on:

- purge everything or specific URLs
- toggle development mode
- set the SSL mode
- create, update or delete DNS records
- block an IP

Bunny.net supports cache purges. Destructive actions need a typed
confirmation.

### Cloud accounts

A cloud connection is **proven** when you save it. DevOps EnvMap asks the cloud
who the credential belongs to (AWS STS, an Azure AD token grant, Alibaba STS),
so a key for the wrong account is caught at save time.

- **AWS:** read across EC2, EBS, VPC, ELB, RDS, ElastiCache, S3, ECR and
  Lambda. The actions are:
  - instances: start, stop, reboot, tag and snapshot
  - security groups: create, authorize, revoke and delete
  - IAM users: create and delete, attach and detach policies, and create,
    disable or delete access keys
  - ECR repositories: create, set tag mutability, set scan-on-push, and delete
    images or repositories
  - Elastic IPs: associate and unassociate
- **Alibaba Cloud:**
  - ECS instances: start, stop, reboot and tag
  - a browser console, and commands run through Cloud Assistant
  - security groups, RAM users, policies and keys, vSwitches and EIPs
- **Azure:** the credentials are verified with a management-plane token
  grant.
- **Google Cloud** and other APIs: the credentials are stored and checked for
  the right structure.
- **Bills** read into IT spend, and CSV exports of what each account holds.

Every action declares how risky it is (safe, care or removal), and the form,
the confirmation and the audit entry all read from that one declaration.

### Server hardware

**Redfish**, which covers Dell iDRAC, HPE iLO, Lenovo XCC and Supermicro with
one implementation. The vendor is detected, not configured. You get systems,
chassis, health and firmware inventory for every machine, read-only.

### Hypervisors

**Proxmox VE, and vCenter or standalone ESXi.** Hosts and their virtual
machines: the layer underneath the Kubernetes nodes, where "the node went
away" usually gets explained. These pages are read-only by design. There is no
start, stop, migrate or snapshot here, because both tools have their own
consoles, permissions and audit trails. Power buttons exist only for the VMs
DevOps EnvMap provisioned itself.

### Storage devices

**Synology DSM, TrueNAS, MinIO, S3-compatible endpoints, NFS servers, SMB/CIFS
shares**, and anything else with a URL. These are the boxes backups land on.
Each is registered and health-checked, with a Test button and a status line
that says when it last answered.

### Databases

**PostgreSQL, MySQL/MariaDB and Couchbase.** A registered server holds **no
username and no password**. You open a session with your own credentials, and
they last only as long as the session.

- **SQL databases:** tabs for overview, tables (browse rows), a query console,
  roles, activity and locks. Statements that change data stay refused until
  you switch writing on for the session and type `write`. You can export one
  table or database as SQL, or everything as a zip.
- **Couchbase:** tabs for overview, buckets, XDCR, indexes, query and users.

### VPN portals

**Pritunl, OpenVPN Access Server, wg-easy and Netmaker.** Is the tunnel up,
and who is on it? When an internal endpoint is unreachable, the VPN is usually
the first question.

### Server assets

A record of what the team actually operates: physical machines, VMs, cloud
instances and appliances. It holds the details you need when something breaks
at 02:00, and the ones finance asks for at renewal time.

- **Fields:** hostname, serial or service tag, model, kind, status, owner,
  project, region, environment, placement, provider, location, CPU cores,
  memory, disk, operating system, address, management address, purchase date,
  warranty end, tags, notes, and any custom `name: value` fields.
- **Nothing is predefined.** Suggestions grow out of what you have already
  entered.
- **Search** across every field at once. Filters and breakdowns are built from
  the data, and totals follow whatever is filtered.
- **Warranty flags**, which feed the expiry radar.
- **CSV in and out.** Rows are matched on serial first and hostname second, so
  re-uploading updates rows instead of duplicating them. A column named
  `attr_something` becomes a custom field.
- The inventory is **entered, not discovered**. It is the record of what you
  believe you have, which is what you compare reality against. Ansible and
  Privileged Access both read hostnames from it.

### IT spend

What you pay for, to whom, how often, and what lapses next month.

- **Kinds:** subscriptions, perpetual licences and pay-as-you-go.
- **Categories:** SaaS, cloud, hosting, domain, certificate, plugin, security,
  support and other.
- **Billing cycles and renewal dates**, with a monthly view.
- **Currency conversion** to one reporting currency, and CSV export.
- **Cloud bills** read from each connected cloud account.
- Renewals feed the expiry radar.

### Ansible

- **Playbooks** are kept in the portal with every version retained, and scoped
  to a project and region.
- **Host groups and hosts.** Hosts can be taken from the server inventory
  instead of retyped, and their addresses keep following it. Every group, host
  and playbook carries an environment classification (production, staging,
  dev), shown as a coloured badge.
- **`--check` is the first button; a real run is the second.** Real runs stay
  off until the installation permits them, they need their own permission, and
  a production group needs its name typed.
- **Schedules**, with claim-based firing, so two portals over one database
  never fire the same run twice.
- **Every run keeps** the exact command, the whole output and Ansible's own
  recap. The record afterwards is the run itself.
- **An SSH terminal** to any host in a group, recorded by Privileged Access.
- An SSH key is checked by `ssh` itself when you save it, so a mangled paste
  is caught at the form and not in a failed run.

### Terraform and infrastructure provisioning

**Terraform stacks.** A stack is the `.tf` files, their variables and a
sealed provider credential. At run time the credential is injected as
environment variables, never written to a file.

- **Runs:** `init`, `plan`, `apply` and `destroy`, each run on its own with its
  output kept.
- **State:** each stack keeps a persistent working directory, so state and
  downloaded providers survive between runs.
- **Gates:** `apply` and `destroy` need the installation's permission, and a
  production stack needs its name typed. Even a `plan` needs the run
  permission, because it executes provider code with the credential.
- **Revisions:** every saved version of a stack is kept, and an earlier one can
  be restored.
- **Engine:** the image ships OpenTofu, and `PORTAL_TERRAFORM` selects another
  binary.

**Provision a VM** is a wizard on top of the stack engine. It never provisions
anything itself. It generates an ordinary stack, so the same runs, gates,
production confirmation, audit and permissions apply.

- **Targets:** AlmaLinux 10 or 8 VMs (cloud image, with a static IP through
  cloud-init), or a **Talos Kubernetes cluster** whose nodes configure
  themselves from a config drive at first boot.
- **Live reads from Proxmox:** nodes, datastores, bridges and image presence,
  using a connection's sealed credential that never reaches the browser. It
  warns when a datastore lacks the `snippets` content type Talos needs.
- **Several Proxmox hosts in one run**, with one aliased provider each.
- **After it is built:** download the cluster's kubeconfig and talosconfig,
  run a post-provision Ansible playbook, and open the VM's **console in the
  browser** (noVNC). VM power buttons are on every row.

### Privileged Access (PAM)

An installation switch, off by default, at **Settings → Privileged Access**.
When it is on, it is one place to open a live session on a machine or an
application. The credential is brokered, so nobody sees it. The session is
recorded, and every connect, command and refusal is audited.

- **Targets:** a machine or application plus a protocol: SSH, RDP, VNC, HTTPS
  or HTTP, PostgreSQL or MySQL. Every Ansible inventory host appears
  automatically, so a host is never entered twice. Rows carry a hostname and
  a label, and a search box finds them.
- **Brokered credentials.** Secrets are sealed at rest and only ever handed to
  `ssh` or the gateway, never to a page.
- **SSH sessions:** recorded as a replayable cast plus a redacted command
  transcript. **File transfer** runs over the session's own SFTP, with a
  folder tree like FileZilla's and upload and download progress. Every
  transfer is audited by name, direction and size, refusals included.
- **RDP and VNC** through the Apache Guacamole sidecar, recorded and
  replayable in the browser.
- **Recorded web sessions.** A short-lived browser pod in a cluster you choose
  opens the application. You work through it, and the session is recorded like
  a desktop.
  - **One pod per session**, so two people never share cookies.
  - **Confined:** a NetworkPolicy and DNS rules confine the browser to that one
    application.
  - **Fail closed:** it refuses to open if the application's host cannot be
    confined.
  - **Warm pool:** a pool of ready browsers keeps opening fast.
- **Supervision.** Watch a live SSH session as it happens, watch or take over
  a live desktop session, and end any session.
- **Governance:**
  - a required reason for access (off, production only, or always)
  - an idle timeout, a maximum duration and a per-person concurrent-session cap
  - a production target's name typed before a session opens
- **Recording integrity.** Each recording carries a SHA-256 taken when it was
  filed, and the replay page shows *verified*, *altered*, *missing* or
  *expired*.
- **Retention.** Recordings are kept by age or total size. The recording file
  is removed and the audit row stays.
- **Scoped access.** Reading the catalogue, connecting, and deleting or killing
  are separate grants. A role can be limited to specific targets.

### The assistant

Ask about the estate in plain language: "which pods are crash-looping in
preprod?", "what changed before the alert?", "which certificates expire this
month?".

- **It answers by querying.** It runs 34 real queries over the live database
  and caches, instead of describing the estate from a summary, and it looks
  more than once when the first answer raises a question.
- **It can propose a cluster action and carry it out once you confirm**:
  restart, scale, roll back, delete a pod, cordon, uncordon, drain, install
  metrics-server, or an Argo CD sync. The same gates as the UI apply, including
  the person's permissions, the cluster's management tick and a production
  name typed. The wider set of verbs is available to AI clients over MCP,
  below.
- **Providers:** Anthropic, any OpenAI-compatible endpoint, or Ollama running
  locally, including the optional in-chart Ollama. Each person can bring their
  own model account, so their questions go to their own spend.

### AI clients over MCP

DevOps EnvMap serves itself as an **MCP server** at `/mcp` (Streamable HTTP,
JSON-RPC 2.0), so Claude Desktop, Claude Code or any MCP client can work with
the estate.

- **Tokens.** A personal token belongs to one person and can be narrower than
  its owner, never wider. You choose which areas it reads, whether it may only
  read or may also act, and optionally which actions. Presets cover the usual
  choices: *read and troubleshoot*, or *full access*. The secret is shown once
  and stored only as a hash.
- **28 verbs** beside the read catalogue. They include reading logs and
  describing objects (`kubectl_read` is read-only for every cluster), running
  playbooks and Terraform, provisioning VMs, requesting certificates, syncing
  GitOps applications, reading, changing and committing values files, and
  registering projects, regions, environments and clusters.
- **Two switches.** The server is **off on a new installation**, and when off
  it answers 404. Actions are a second switch, off again. Users, roles and
  tokens are never reachable from MCP.
- **Auditing.** Every refusal is audited, and reads are counted per token.

---

## Sign-in, users, roles and audit

**Local accounts.** The username is an email address. Passwords are scrypt
hashes with per-user salts. **TOTP two-factor authentication is mandatory**,
and an account reaches no page until it has enrolled. Sessions are signed
cookies with a configurable lifetime (8 hours by default).

**Passkeys.** Sign in with Touch ID, Windows Hello, an Android phone or a
security key, with nothing to configure.

- **A passkey replaces both factors.** User verification is required at
  enrolment and at every sign-in.
- **Autofill:** landing on the sign-in page offers the passkey in the email
  field's autofill.
- **Compatibility:** it works across operating systems, including RSA keys for
  TPM-backed Windows Hello, and across subdomains when `PORTAL_PASSKEY_RPID`
  is set.
- **No biometric data:** the portal stores public keys only.
- **Password and TOTP always remain as a way in.**

**Microsoft Entra ID.** OpenID Connect sign-in beside local accounts, turned
on by an administrator in the running portal.

**Invitations and password resets.** These are one-time links that expire and
are stored only as a hash. Configure SMTP under **Settings → Email** and they
are sent by email, so "we verified their address" is true.

**Your account** (`/me`): name, password, authenticator, passkeys, your own
model account for the assistant, your MCP tokens, your theme and your own
recent activity. Replacing an authenticator needs the password and a valid code
from the app being replaced.

**Roles.** Permissions are **areas**, one per page or capability (33 in
total). A role is any set of areas, and it can be scoped to specific projects,
clusters or Privileged Access targets. Areas that hand over the keys are
marked as escalating and treated with care: settings, users, cluster
management, running Ansible for real, applying Terraform, and connecting to
Privileged Access targets.

**Audit log.** It records logins, MFA changes, user and role changes,
connections added or removed, values saved and pushed, cluster actions, runs,
certificate and key downloads, privileged sessions with their stated reason,
and every refusal. Each entry carries the actor, target, outcome and client IP.

- **Tamper-evident:** every row is HMAC-chained to the one before it, and a
  one-row anchor records the tip and the count. Editing, deleting, reordering
  or trimming rows breaks the chain, and the audit page verifies it.
- **Searchable:** filter by action, person, category and date range, with real
  paging and CSV export.

---

## Administration

- **Settings** has a search box across all 22 sections. It understands the
  words people actually type: `smtp` finds Email, `k8s` finds clusters, `cve`
  finds security scanning, `argo` finds GitOps.
  - **Estate:** Projects, Kubernetes clusters, GitOps controllers, Pipelines,
    Security scanning, Log platforms, Monitoring, Workflow engines, Edge & DNS,
    Cloud accounts, Server hardware, Hypervisors, Storage devices, Database
    servers and VPN portals.
  - **Engines:** Ansible, Terraform and Privileged Access.
  - **The installation:** Assistant, AI clients (MCP), Email and Deployment.
- **TLS per connection.** Every connection may skip TLS verification for an
  internal server with a self-signed certificate. It is per connection, never
  global, and shown as a warning badge wherever the connection appears.
- **Scope per connection.** A connection can be global, with one server for
  every project, or scoped to a single project.
- **Settings → Deployment** shows what the environment told this installation:
  every `PORTAL_*` value and where it came from, and the versions of `kubectl`,
  `git` and `kubeseal` it found.
- **About** shows the running version, the update channel and the one-click
  update.
- **Branding** can be set in Settings or through `PORTAL_BRAND_*`. The
  environment wins, which suits a container.

---

## Security model

**Cluster access.** A read-only ServiceAccount is enough for every page, and it
is the default posture. With nothing else configured, DevOps EnvMap only lists
and reads. It never applies, patches, deletes, execs or port-forwards.
Management is opt-in per cluster and per person, as described above.

**Write paths.** There are four, and each is gated:

- files in the local checkout, and your git remote
- a cluster, only where management was turned on
- the systems whose connections have actions (Argo CD, Cloudflare, AWS,
  Alibaba Cloud, databases)
- Ansible and Terraform runs

**Credentials at rest.** These credentials in the database are sealed with
Fernet under `PORTAL_SECRET_KEY`:

- every integration token
- repository credentials
- Privileged Access, Ansible and Terraform credentials
- certificate private keys
- each person's own model key

Kubeconfigs, sealing certificates and deploy keys are files that `kubectl`
and `ssh` read from disk. They are stored under `secrets/` with `0600`
permissions. Database servers store no credentials at all. MCP token secrets
and one-time links are stored as hashes only.

**In the browser.**

- **A strict Content-Security-Policy.** `script-src 'self'` with a per-request
  nonce, and no `unsafe-inline` and no `unsafe-eval`, so an injected script or
  event handler is refused by the browser. `frame-ancestors 'none'` and
  `object-src 'none'` apply too.
- **Headers:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: same-origin` and a same-origin opener policy.
- **Escaping:** operator text is escaped everywhere, and another system's text
  (scanner findings, Grafana text panels) goes through an
  escape-everything-first renderer or an allowlist sanitiser.
- **Form recovery:** after a refused submit, form values are restored, but a
  password, a key or a kubeconfig is never kept in browser storage.

**Outbound requests.** Every request to an address typed into a settings form
passes one URL guard first. Only `http` and `https` are allowed, so a
`file://` URL cannot read the portal's own disk.

**The container.**

- **Runs as:** UID 10001, with a read-only root filesystem, all capabilities
  dropped and `RuntimeDefault` seccomp.
- **Contents:** bytecode only, with no `.py` source.
- **Release gates:** the release pipeline refuses an image that cannot import
  its own entry point or that disagrees with `VERSION`.
- **Signing:** images are signed keylessly with cosign.

**Sessions and requests.** Session cookies are signed and can be restricted to
HTTPS (`portal.cookieSecure`). Forwarded headers from the ingress are trusted,
so the portal knows it is served over HTTPS. The `/healthz` endpoint reveals
only the version.

---

## The data model

```
project                     a product or platform; owns clusters and regions
 ├── clusters               a shared pool; one cluster can serve many environments
 └── region                 a locality, or any grouping you like
      └── environment       dev, staging, prod…, each with its own git binding
           └── service      one *-values*.yaml file in the environment's folder
```

**Regions do not have to be geographic.** A region is whatever grouping owns a
set of environments: a business unit, a tenant or a product line. A two-letter
region name shows its country flag automatically, and any other name shows a
globe or an emoji you choose.

**Environments are declared on the cluster that serves them.** Each carries a
complete binding (repository, branch, path, protocol and credentials), and
nothing is inherited from anywhere else, so what a form shows is exactly what
is used. One cluster can serve several environments, and its form carries one
block per environment. The mapping appears from both ends: each cluster lists
its environments, and each environment names its cluster.

**Repository layout.** Any layout works. The path is part of each
environment's binding, and a project can set a layout pattern with `{env}` and
`{svc}` when its files are not one folder per environment. The default shape
looks like this:

```
<repo>/
└── charts/microservice/environments/
    ├── dev/
    │   ├── api-values.yaml
    │   └── worker-values.yaml
    ├── staging/
    └── prod/
```

Inside a values file, both shapes are read:

```yaml
configMap:
  data:
    KEY: value
secret:
  secretName: my-secret
  SealedSecret:
    KEY: AgB…
```

```yaml
config:
  KEY: value
SealedSecret:
  KEY: AgB…
```

---

## Where data lives

Everything lives under `PORTAL_DATA_DIR` (`/data` in the chart). Nothing else
on the host is touched.

| Path | Contents | Sensitivity |
|---|---|---|
| `portal.db` | projects, regions, clusters, connections and their sealed tokens, accounts, roles, the audit log, inventory, spend, Ansible and Terraform records, certificate orders | **high** |
| `secret.key` | the sealing key, written only when `PORTAL_SECRET_KEY` is not set | **high**: keep it apart from database copies |
| `session.key` | the cookie-signing key; delete it to end every session | high |
| `secrets/` | kubeconfigs, sealing certificates, deploy keys | **high** |
| `repos/` | git checkouts, one per repository and branch | disposable |
| `tf-stacks/` | each Terraform stack's working directory and state | important |
| `pam-sessions/` | session recordings | evidence, kept under the retention policy |
| `backups/` | the database copy taken before each version change | keep |

Directories are `0700` and files `0600`. The data directory must never be
committed, and the shipped `.gitignore` excludes it.

**Backups.** Back up `portal.db` (take a copy with
`sqlite3 portal.db ".backup out.db"`, or copy it while the portal is stopped),
the key, and `tf-stacks/`. The checkouts are disposable, and the portal clones
them again.

**One database.** State is a single SQLite file in WAL mode. That choice is
about correctness: transactions stop two people saving at once from silently
losing an edit. SQLite itself ships with Python, so there is no database
server to run, and the SQL is deliberately portable, so moving to PostgreSQL
would be a driver change. Each module registers its own tables, and
migrations are additive.

---

## Configuration reference

Everything a deployment decides is read once at startup and shown on
**Settings → Deployment**, with its value and whether it came from the
environment or a default. Projects, clusters, repositories, integrations and
every credential are **not** environment variables. They change while the
portal runs, and a chart upgrade must never overwrite them.

| Variable | Default | Purpose |
|---|---|---|
| `PORTAL_DATA_DIR` | `<code>/data` | database, checkouts, secrets and recordings. Mount a volume here |
| `PORTAL_HOST` / `PORTAL_PORT` | loopback / `8471` | where to listen |
| `PORTAL_ALLOW_NETWORK` | unset | must be `1` to bind a non-loopback address |
| `PORTAL_ROOT_PATH` | unset | URL path prefix behind an ingress |
| `PORTAL_BASE_URL` | unset | the public address, used for links in emails |
| `PORTAL_COOKIE_SECURE` | unset | `1` keeps the session cookie on HTTPS only |
| `PORTAL_SESSION_HOURS` | `8` | session lifetime |
| `PORTAL_SECRET_KEY` | unset | the key that seals stored credentials and keys the audit chain |
| `PORTAL_KUBECTL`, `PORTAL_KUBESEAL`, `PORTAL_GIT`, `PORTAL_SSH`, `PORTAL_SFTP` | the plain names | tool binaries, by name or absolute path |
| `PORTAL_ANSIBLE`, `PORTAL_ANSIBLE_INVENTORY` | `ansible-playbook`, `ansible-inventory` | the Ansible binaries |
| `PORTAL_TERRAFORM` | `terraform`, then `tofu` | the Terraform engine |
| `PORTAL_TOOL_PATH` | inherited `PATH` | the `PATH` handed to the tools |
| `PORTAL_SCHEDULER` | on | `0` keeps the Ansible schedule ticker off, for a pod that must not fire anything |
| `PORTAL_METRICS_URL` | upstream `components.yaml` | where metrics-server is installed from; point it at a mirror on an air-gapped site |
| `PORTAL_DNS_RESOLVERS` | unset | resolvers for the certificate page's TXT check. Unset means the zone's own nameservers, then `resolv.conf`, then public resolvers |
| `PORTAL_NETSHOOT_IMAGE`, `PORTAL_NETSHOOT_TTL` | netshoot, `1800` s | the Troubleshoot pod's image and lifetime |
| `PORTAL_PASSKEY_RPID`, `PORTAL_PASSKEY_ORIGIN` | derived from the request | for a proxy that hides the real host, or one install reached at several hostnames |
| `PORTAL_UPDATE_URL` | unset | the release feed the About page checks |
| `PORTAL_SELF_UPDATE` | unset | set by the chart from `rbac.selfUpdate`, with `PORTAL_SELF_DEPLOYMENT`, `PORTAL_SELF_CONTAINER` and `PORTAL_SELF_NAMESPACE` |
| `PORTAL_ASSISTANT_PROVIDER`, `_URL`, `_MODEL`, `_ENABLED` | unset | seed the assistant's configuration |
| `PORTAL_PAM` | unset | seeds the Privileged Access switch on a first start; the switch in Settings wins afterwards |
| `PORTAL_BRAND_NAME`, `PORTAL_BRAND_ORG`, `PORTAL_BRAND_SHORT` | the default brand | the product name, subtitle and authenticator issuer |

Cache lifetimes, timeouts and page sizes are module constants. Per-connection
page sizes are editable in the UI.

---

## Performance

DevOps EnvMap talks to slow, remote systems, often over a VPN, so the rules
are:

- **Nothing that can be cached is fetched twice.** Stale data renders
  immediately while one background refresh runs, single-flight per key. The
  **Refresh** button on any page bypasses the cache for that page.
- **No page waits for the slowest source.** A page built from many clusters
  or connections paints within 0.4 s. It shows what arrived, names what is
  still being read, and fills in behind. The timeline and the expiry radar
  wait at most 1.5 s.
- **Caches are warmed before anybody asks**, so the first visit after a
  restart is not the slow one.
- **Fetch per screen, not per page.** A large DefectDojo holds tens of
  thousands of findings. Asking each screen only for what it renders brought a
  30-second page to 2 seconds.
- **Independent reads run in parallel** (a cluster's nodes, pods and metrics,
  an Argo CD application and its tree), but fan-out is capped where
  measurement showed a system gets slower under parallel load.
- **Shared assets are cached for a year** and versioned per release, and
  responses are gzipped. Charts are server-rendered SVG with no client-side
  chart library.

---

## Extending it

Each integration is a registry plus one function per capability. To add a
provider, for example a fifth CI system:

1. Add an entry to `PROVIDERS` in the module (`ci.py`, `security.py`,
   `logstore.py`, `monitoring.py`, `gitops.py`, `workflows.py`, `edge.py`,
   `vpn.py`, `virt.py`, `stordev.py`, `dbconn.py`, `cloud.py`), with a label,
   an icon, a URL hint, the fields it needs, and a note on which credential to
   create.
2. Write the fetch function, returning the module's normalised shape.
3. Register it in the module's dispatch table.

The settings form, the connection test, the provider boxes, the drill-down
and the Overview roll-up are all driven by the registry, so a new provider
appears everywhere at once.

**Two rules keep the code portable.**

- **Anything describing an environment is configuration.** Service names, key
  prefixes, index patterns, hostnames and networks belong in settings. A
  default may exist, but it must be neutral and overridable.
  `tests/test_nohardcoding.py` enforces it, against names you supply in
  `PORTAL_PRIVATE_NAMES`, and it refuses anything shaped like a credential.
- **Anything describing a protocol stays in code.** API paths, auth header
  formats, a vendor's severity names and git's default branch names stay
  fixed. Making these configurable would break integrations, not adapt them.

When a heuristic is unavoidable, such as detecting a log field or matching a
cluster to an environment, it must be overridable, match whole tokens rather
than substrings, and fail visibly rather than guess.

---

## Development and releasing

```bash
for t in tests/test_*.py; do ./.venv/bin/python "$t"; done
```

The tests are 73 plain scripts, not pytest. Each prints `OK` or `N FAILED` and
exits non-zero on failure. They include a software WebAuthn authenticator, a
fake Argo CD, a fake DefectDojo, template sweeps for the CSP rules, and a
Helm-rendering chart test. A test must be load-bearing: after writing one,
revert the fix it covers and confirm it fails.

**Releasing** is done from the repository's **Actions** tab. The `release`
workflow takes a version and a one-line note. It then bumps `VERSION` and the
chart, commits, tags and pushes, builds `linux/amd64` and `linux/arm64`, and
checks the built image imports its entry point, ships no source and agrees
with `VERSION`. Finally it signs the image with cosign, pushes the image and
the OCI chart, and attaches the chart package to the GitHub release. The
workflow refuses a `v` prefix, a version already released, a downgrade and an
existing tag.

`scripts/release.sh VERSION` does the same build and checks locally and
pushes nothing. `.github/workflows/check.yml` runs on every push. It renders
the chart in the configurations people actually use, imports every module, and
refuses anything that looks like a database, a kubeconfig, a key or an absolute
home path.

---

## Troubleshooting

**A cluster shows "unreachable".** Check the kubeconfig and context on its
form, and that the API server is reachable from the portal (VPN, routing). The
cluster page says which of the two failed.

**A service shows "cannot be read".** Its values file did not parse. The
window names the YAML error and its line.

**A push says the branch is protected.** Push to a new branch from the commit
dialog and open a merge request in your git host.

**A certificate order waits on DNS.** The order page shows each TXT record and
whether it can be seen yet, asking the zone's own nameservers where it can.
If the record is published but invisible, check that it was created in the
zone that actually serves the name.

**Log columns are empty.** Field detection did not recognise the document. The
raw document is shown, so you can read the field names and set them on the
connection.

**A Grafana panel says it is not drawn here yet.** That panel type is not
rendered natively yet, and the link opens it in Grafana.

**Passkeys are unavailable.** The portal must be reached over HTTPS at a domain
name, not an IP address. `localhost` and the loopback addresses are the only
exceptions.

**"Refusing to bind…" at startup.** This is intentional. Set
`PORTAL_ALLOW_NETWORK=1` only behind TLS and an ingress.

**A TLS error on an internal server.** Tick *skip TLS verification* on that one
connection. Better still, fix the certificate.

**The pod restarts with exit code 137.** It ran out of memory. Raise
`resources.limits.memory`; a large estate needs 2Gi to 4Gi.

**Something is slow.** Pages say which source they are still waiting on. That
is usually a system not answering, not slow code.

---

## Known limitations

- **One node's volume.** SQLite's WAL is not safe over a network filesystem,
  so replicas must share one node's volume, and the chart co-schedules them.
  That scales capacity. Surviving a node failure would need an external
  database, which is not implemented.
- **Ending a Privileged Access session is per replica.** A live session belongs
  to the replica that holds it. The catalogue, recordings and audit are shared.
- **Recorded web sessions reach one host.** An application that also calls a
  second hostname does not work inside a recorded web session yet.
- **Not in Privileged Access yet:** just-in-time access requests with approval,
  command filtering, automatic credential rotation and break-glass access. It
  also has no query console of its own; the Databases page has one.
- **Certificate TXT records are yours to create.** This is deliberate. The zone
  that needs the record is often not one the portal holds a token for.
- **Read-only integrations.** Pipelines, workflow engines, security scanners,
  log platforms, server hardware, hypervisors, storage devices, VPN portals
  and Flux are read-only.
- **Single sign-on is Microsoft Entra ID only.** Generic OIDC and SAML
  providers are not supported yet.
- **Trend history is short.** It is a rolling sample for sparklines, not a
  metrics store. Use Prometheus for retention.

---

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests are welcome. The tests are plain scripts (see
[Development and releasing](#development-and-releasing)), and a new test must
fail against the code it fixes before it passes against the fix.

This repository is published from a private development repository as a
single commit per release. Pull requests are applied upstream and arrive here
with the next release.
