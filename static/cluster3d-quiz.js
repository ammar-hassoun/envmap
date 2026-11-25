/* The experts of the city, and what they know.

   Eight people stand in the streets of the city (cluster3d-city.js), one for
   each job a platform team has. Each tells you how the clusters are, from the
   same facts the street is drawn from, and each asks Kubernetes questions in
   its own subject. Answer one and it cheers, and the first time it gives you
   something to keep.

   This file is what they know, and nothing that draws: the questions, who
   asks which, what each says of the clusters, and how a question is chosen
   and marked. It runs under node, so every question is checked for its shape
   by tests/test_city.py.

   A QUESTION is [subject, question, the right answer, three wrong ones, why].
   The right answer is written first and the four are shuffled when asked, so
   there is no index to get wrong. Each is a fact about Kubernetes itself and
   is true of any cluster: nothing here is about one installation. */
(function () {
  'use strict';
  var Q = [
    // ── basics: what the thing is ───────────────────────────────────────
    ['basics', 'What is the smallest thing Kubernetes deploys and runs?', 'A pod', 'A container', 'A node', 'A deployment', 'A pod is one or more containers that share a network address and storage. Kubernetes schedules pods, not bare containers.'],
    ['basics', 'What does the word Kubernetes mean?', 'Helmsman, in Greek', 'Container ship, in Dutch', 'Orchestra, in Latin', 'Cluster, in German', 'It is Greek for helmsman or pilot, which is why its logo is a ship\'s wheel.'],
    ['basics', 'Why is Kubernetes shortened to K8s?', 'There are eight letters between the K and the s', 'It was the eighth version of the project', 'It runs on eight machines by default', 'Eight companies founded it', 'K, then eight letters (ubernete), then s.'],
    ['basics', 'How many spokes does the wheel in the Kubernetes logo have?', 'Seven', 'Six', 'Eight', 'Twelve', 'Seven: a nod to the project\'s first code name, Project Seven of Nine.'],
    ['basics', 'Which company first designed Kubernetes before giving it to a foundation?', 'Google', 'Red Hat', 'Docker', 'Amazon', 'Google built it from what it had learned running its own systems, and donated it to the Cloud Native Computing Foundation.'],
    ['basics', 'What is a node?', 'A machine, real or virtual, that runs pods', 'A group of pods with the same label', 'A copy of the cluster\'s database', 'A network rule', 'A node is a worker machine. The kubelet on it runs the pods the scheduler places there.'],
    ['basics', 'What is the control plane?', 'The parts that decide and record what the cluster should run', 'The network between the pods', 'The node with the most memory', 'The dashboard', 'The API server, etcd, the scheduler and the controllers: they hold the desired state and work to make it true.'],
    ['basics', 'Which part of the control plane does everything else talk to?', 'The API server', 'etcd', 'The scheduler', 'The kubelet', 'Every component, and kubectl, goes through the API server. It is the only one that reads and writes etcd.'],
    ['basics', 'Where does a cluster keep its state?', 'In etcd', 'In the kubelet', 'In a ConfigMap', 'On each node\'s disk', 'etcd is the key-value store that holds every object in the cluster.'],
    ['basics', 'What runs on every node and starts the containers of the pods placed there?', 'The kubelet', 'The scheduler', 'The controller manager', 'CoreDNS', 'The kubelet watches for pods assigned to its node and has the container runtime start them.'],
    ['basics', 'What is a namespace for?', 'Dividing a cluster\'s objects into named groups', 'Giving a pod its IP address', 'Encrypting Secrets', 'Naming the nodes', 'A namespace scopes names, and is where quotas and access rules are usually set.'],
    ['basics', 'What does "declarative" mean in Kubernetes?', 'You describe the state you want and the cluster works toward it', 'You run commands in a fixed order', 'Every change needs approval', 'Configuration is written in JSON only', 'You declare the desired state. Controllers compare it with what exists and close the gap, again and again.'],
    ['basics', 'What does a controller do?', 'Compares what is wanted with what exists, and corrects the difference', 'Routes traffic into the cluster', 'Stores container images', 'Signs certificates for users', 'That loop of watching and correcting is called reconciliation.'],
    ['basics', 'What is a label?', 'A key and value on an object, used to select it', 'The name of a container image', 'A node\'s hostname', 'A comment the cluster ignores', 'Selectors find objects by their labels: it is how a Service finds its pods.'],
    ['basics', 'Which command-line tool talks to a cluster?', 'kubectl', 'kubeadm', 'kubelet', 'kube-proxy', 'kubectl sends your requests to the API server. kubeadm builds clusters and the kubelet runs on nodes.'],
    ['basics', 'What is a container image?', 'A packaged filesystem and settings that a container is started from', 'A screenshot of a running pod', 'A backup of etcd', 'A node\'s operating system', 'An image is the read-only package. A container is a running instance of it.'],
    ['basics', 'Which three interfaces let Kubernetes swap its runtime, network and storage?', 'CRI, CNI and CSI', 'API, CLI and GUI', 'TCP, UDP and HTTP', 'RBAC, PSA and OPA', 'Container Runtime Interface, Container Network Interface and Container Storage Interface.'],

    // ── workloads: what runs, and how it is rolled out ──────────────────
    ['workloads', 'You delete a pod that belongs to a Deployment. What happens?', 'Its ReplicaSet starts another to replace it', 'The Deployment is deleted too', 'Nothing: the count stays one lower', 'The node is drained', 'The ReplicaSet keeps the number of pods at the count it was given. To have one fewer you scale it down.'],
    ['workloads', 'What does a Deployment manage directly?', 'ReplicaSets', 'Pods, one by one', 'Nodes', 'Services', 'A Deployment creates a ReplicaSet for each version, and the ReplicaSet creates the pods.'],
    ['workloads', 'What is the default update strategy of a Deployment?', 'RollingUpdate', 'Recreate', 'BlueGreen', 'Canary', 'RollingUpdate replaces pods a few at a time. Recreate stops them all first.'],
    ['workloads', 'In a rolling update, what does maxSurge set?', 'How many pods above the wanted count may exist during the update', 'How many pods may be unavailable', 'How long to wait between pods', 'How many old versions are kept', 'maxSurge is the extra pods allowed. maxUnavailable is how many may be missing.'],
    ['workloads', 'Which command takes a Deployment back to its previous version?', 'kubectl rollout undo', 'kubectl rollback now', 'kubectl apply --previous', 'kubectl revert deployment', 'kubectl rollout undo deployment/name returns to the previous revision.'],
    ['workloads', 'Which workload runs exactly one pod on every node?', 'A DaemonSet', 'A StatefulSet', 'A Deployment', 'A CronJob', 'A DaemonSet puts a pod on each node it selects: log shippers and network agents run this way.'],
    ['workloads', 'Which workload gives each pod a stable name and its own storage?', 'A StatefulSet', 'A Deployment', 'A DaemonSet', 'A ReplicaSet', 'StatefulSet pods are named name-0, name-1 and so on, and each keeps its own volume claim.'],
    ['workloads', 'When a StatefulSet is scaled down, which pod goes first?', 'The one with the highest number', 'The one with the lowest number', 'The oldest', 'A random one', 'It removes pods in reverse order, highest ordinal first.'],
    ['workloads', 'What is a Job for?', 'Running pods until a task completes', 'Keeping a service running for ever', 'Running one pod per node', 'Scheduling pods onto nodes', 'A Job runs pods to completion and retries them on failure, up to its backoff limit.'],
    ['workloads', 'What runs Jobs on a schedule?', 'A CronJob', 'A DaemonSet', 'A Timer', 'A ScheduledPod', 'A CronJob creates a Job each time its cron schedule comes round.'],
    ['workloads', 'When do init containers run?', 'Before the app containers, one after another, each to completion', 'At the same time as the app containers', 'After the pod stops', 'Only when the pod crashes', 'Each init container must finish successfully before the next starts, and before any app container does.'],
    ['workloads', 'What is the default restartPolicy of a pod?', 'Always', 'OnFailure', 'Never', 'Once', 'Always. A Job\'s pods must use OnFailure or Never.'],
    ['workloads', 'What is Helm?', 'A package manager for Kubernetes', 'A container runtime', 'A network plugin', 'A kind of Service', 'Helm installs charts: templated sets of manifests, with values you can override.'],
    ['workloads', 'In Helm, what is a release?', 'An installed instance of a chart', 'A tagged container image', 'A Git branch', 'A new Kubernetes version', 'Installing a chart creates a release, which Helm can upgrade or roll back.'],
    ['workloads', 'What does GitOps mean?', 'Git holds the desired state and a tool keeps the cluster matching it', 'Developers push straight to production', 'Every pod clones a Git repository', 'kubectl is replaced by git', 'A tool such as Argo CD or Flux watches the repository and reconciles the cluster to it.'],
    ['workloads', 'Under GitOps you change a Deployment by hand in the cluster. What usually happens?', 'The GitOps tool puts back what Git says', 'Git is updated to match', 'The cluster stops syncing for ever', 'The Deployment is deleted', 'The cluster is reconciled to Git, so a manual change is drift and is reverted. Change it in Git.'],
    ['workloads', 'Which command restarts every pod of a Deployment, a few at a time?', 'kubectl rollout restart', 'kubectl delete deployment', 'kubectl reboot', 'kubectl scale --replicas=0', 'kubectl rollout restart deployment/name triggers a fresh rolling update with the same version.'],
    ['workloads', 'What does kubectl apply do that kubectl create does not?', 'Updates an object that already exists to match the file', 'Deletes the object first', 'Works only on pods', 'Skips validation', 'apply is declarative: it creates or updates. create fails if the object is already there.'],
    ['workloads', 'What does an Operator add to a cluster?', 'A custom resource and a controller that manages it', 'A second API server', 'More nodes', 'A graphical console', 'An Operator pairs a CustomResourceDefinition with a controller that knows how to run one kind of software.'],

    // ── network: how things reach each other ────────────────────────────
    ['network', 'What is the default type of a Service?', 'ClusterIP', 'NodePort', 'LoadBalancer', 'ExternalName', 'ClusterIP gives the Service an address reachable only inside the cluster.'],
    ['network', 'How does a Service know which pods to send traffic to?', 'By a label selector', 'By the pods\' names', 'By the order they started', 'By the node they are on', 'The selector matches labels, and the matching ready pods become its endpoints.'],
    ['network', 'What is the default port range of a NodePort Service?', '30000 to 32767', '80 to 443', '1024 to 2048', '8000 to 9000', 'NodePorts are allocated from 30000 to 32767 unless the cluster is configured otherwise.'],
    ['network', 'What is the full DNS name of a Service called web in the namespace shop?', 'web.shop.svc.cluster.local', 'shop.web.cluster.local', 'web.cluster.shop.svc', 'svc.web.shop.local', 'service.namespace.svc.cluster.local, with cluster.local the default cluster domain.'],
    ['network', 'What makes a Service headless?', 'Setting clusterIP to None', 'Giving it no selector', 'Deleting its endpoints', 'Using type NodePort', 'With clusterIP: None, DNS returns the pods\' own addresses and nothing load-balances.'],
    ['network', 'What does an Ingress route?', 'HTTP and HTTPS traffic from outside to Services', 'Traffic between nodes', 'DNS queries', 'Storage requests', 'An Ingress describes host and path rules for HTTP traffic.'],
    ['network', 'What must be running for an Ingress to have any effect?', 'An ingress controller', 'A second API server', 'A service mesh', 'metrics-server', 'The Ingress object is only rules. A controller such as NGINX or Traefik carries them out.'],
    ['network', 'What provides DNS inside most clusters?', 'CoreDNS', 'kube-proxy', 'etcd', 'The kubelet', 'CoreDNS answers names such as Services for the pods.'],
    ['network', 'What does kube-proxy do?', 'Programs each node so traffic to a Service reaches its pods', 'Proxies kubectl to the API server', 'Pulls images through a cache', 'Encrypts traffic between pods', 'It maintains the rules, with iptables or IPVS, that turn a Service address into a pod.'],
    ['network', 'With no NetworkPolicy at all, which traffic may reach a pod?', 'All of it', 'None of it', 'Only traffic from its own namespace', 'Only traffic from its own node', 'Pods are open by default. A policy that selects a pod is what starts restricting it.'],
    ['network', 'What does a NetworkPolicy need in order to be enforced?', 'A network plugin that supports it', 'A LoadBalancer Service', 'An Ingress', 'A restart of every pod', 'The CNI plugin enforces policies. With one that does not, the object exists and does nothing.'],
    ['network', 'What is a CNI plugin responsible for?', 'Giving pods their network and addresses', 'Storing container images', 'Scheduling pods', 'Issuing certificates', 'Calico, Cilium and Flannel are CNI plugins: they connect the pods.'],
    ['network', 'In a Service, what is targetPort?', 'The port on the pod that traffic is sent to', 'The port clients connect to', 'The port opened on every node', 'The port of the API server', 'port is the Service\'s own. targetPort is the container\'s. nodePort is on the node.'],
    ['network', 'Which Service type asks the cloud for an external load balancer?', 'LoadBalancer', 'ClusterIP', 'ExternalName', 'Headless', 'LoadBalancer builds on NodePort and has the cloud provider provision a balancer in front.'],
    ['network', 'What does an ExternalName Service return?', 'A DNS CNAME to a name outside the cluster', 'The IP of a node', 'A list of pod IPs', 'A load balancer address', 'It maps the Service name to another DNS name, with no proxying.'],
    ['network', 'A pod is running but not ready. Does its Service send it traffic?', 'No: only ready pods are endpoints', 'Yes, always', 'Only half the requests', 'Only from the same node', 'A pod that fails its readiness probe is taken out of the Service\'s endpoints.'],
    ['network', 'Can two pods on different nodes reach each other by pod IP without NAT?', 'Yes: that is a requirement of the Kubernetes network model', 'No: they must use a Service', 'Only with an Ingress', 'Only in the same namespace', 'Every pod gets its own IP and can reach every other pod directly.'],

    // ── storage: where data lives ───────────────────────────────────────
    ['storage', 'What is a PersistentVolumeClaim?', 'A request for storage by a pod\'s owner', 'A piece of storage in the cluster', 'A backup of a volume', 'A kind of Secret', 'A claim asks for size and access mode. It is bound to a PersistentVolume that satisfies it.'],
    ['storage', 'What does a StorageClass make possible?', 'Creating volumes on demand when a claim asks', 'Encrypting Secrets', 'Scheduling pods by disk speed', 'Sharing memory between pods', 'A StorageClass names a provisioner, so a claim can have a volume made for it.'],
    ['storage', 'What does the access mode ReadWriteOnce allow?', 'Mounting read-write by a single node', 'Mounting read-write by many nodes', 'Writing exactly once', 'Reading by one pod only', 'RWO: one node at a time. ReadWriteMany allows many nodes.'],
    ['storage', 'Which access mode limits a volume to one single pod?', 'ReadWriteOncePod', 'ReadWriteOnce', 'ReadOnlyMany', 'ReadWriteMany', 'ReadWriteOncePod. ReadWriteOnce is per node, so several pods on that node could share it.'],
    ['storage', 'A dynamically provisioned volume\'s claim is deleted. What happens by default?', 'The volume is deleted too', 'The volume is kept for ever', 'The volume is given to the next claim', 'The pod is restarted', 'The default reclaim policy for dynamic volumes is Delete. Retain keeps the volume and its data.'],
    ['storage', 'How long does an emptyDir volume last?', 'As long as its pod', 'Until the node reboots twice', 'For ever', 'One hour', 'emptyDir is created with the pod and removed with it. It survives a container restart, not the pod.'],
    ['storage', 'How does a StatefulSet give each pod its own volume?', 'With volumeClaimTemplates', 'With a shared emptyDir', 'With hostPath', 'With a ConfigMap', 'Each pod gets a claim made from the template, and keeps it across restarts.'],
    ['storage', 'What kind of database is etcd?', 'A consistent, distributed key-value store', 'A relational database', 'A document store', 'A time-series database', 'It keeps keys and values, and uses the Raft protocol to agree on them.'],
    ['storage', 'How many members can a three-member etcd cluster lose and keep working?', 'One', 'Two', 'None', 'All three', 'etcd needs a majority. Two of three is a majority, one of three is not.'],
    ['storage', 'Why do etcd clusters usually have an odd number of members?', 'An even number adds no extra tolerance for failures', 'Odd numbers are faster', 'Kubernetes refuses even numbers', 'It saves disk space', 'Four members still tolerate only one failure, the same as three.'],
    ['storage', 'How is etcd backed up?', 'By taking a snapshot', 'By copying a ConfigMap', 'By restarting the API server', 'It cannot be backed up', 'etcdctl snapshot save writes a consistent copy that a cluster can be restored from.'],
    ['storage', 'What is CSI?', 'The Container Storage Interface', 'The Cluster Security Index', 'The Core Service Ingress', 'The Container Scheduling Interface', 'It is the standard through which storage systems plug into Kubernetes.'],
    ['storage', 'A ConfigMap is mounted as a volume and then changed. What happens in the pod?', 'The files are updated after a short delay', 'Nothing until the pod is recreated', 'The pod crashes', 'The volume is unmounted', 'Mounted ConfigMaps are refreshed. Values read as environment variables are not: those need a restart.'],
    ['storage', 'Why is a hostPath volume risky?', 'It ties the pod to one node\'s disk and exposes the host', 'It is always read-only', 'It deletes data on restart', 'It needs a cloud provider', 'The data lives on one node, and a pod that can mount host paths can read the host.'],
    ['storage', 'Can a PersistentVolumeClaim be made larger after it is bound?', 'Yes, if its StorageClass allows volume expansion', 'Never', 'Only by deleting it', 'Only for emptyDir', 'With allowVolumeExpansion on the class, you raise the request and the volume grows.'],
    ['storage', 'What does a StatefulSet need for its pods\' stable network names?', 'A headless Service', 'An Ingress', 'A LoadBalancer', 'A NetworkPolicy', 'The governing headless Service gives each pod a DNS name such as db-0.db.'],

    // ── security: who may do what ───────────────────────────────────────
    ['security', 'Are Secrets encrypted by default?', 'No: they are only base64-encoded unless encryption at rest is set up', 'Yes, with AES', 'Yes, with the cluster\'s CA', 'Only in kube-system', 'base64 is an encoding, not encryption. Anybody who can read the Secret can decode it.'],
    ['security', 'What is the difference between a Role and a ClusterRole?', 'A Role belongs to one namespace, a ClusterRole to the whole cluster', 'A Role is for people, a ClusterRole for pods', 'A ClusterRole cannot be bound', 'There is none', 'A ClusterRole can also grant cluster-wide things such as nodes.'],
    ['security', 'What gives a Role\'s permissions to a user or a service account?', 'A RoleBinding', 'A Secret', 'A NetworkPolicy', 'A ConfigMap', 'The Role says what may be done. The RoleBinding says who may do it.'],
    ['security', 'What identity does a pod use to call the API server?', 'A ServiceAccount', 'The node\'s root user', 'The kubeconfig of whoever deployed it', 'None: pods cannot call it', 'Each pod runs as a ServiceAccount, the default one of its namespace unless told otherwise.'],
    ['security', 'Which command asks whether you are allowed to do something?', 'kubectl auth can-i', 'kubectl whoami --can', 'kubectl check rbac', 'kubectl permit', 'For example: kubectl auth can-i delete pods.'],
    ['security', 'What are the three Pod Security Standards?', 'Privileged, Baseline and Restricted', 'Low, Medium and High', 'Open, Closed and Locked', 'Dev, Test and Prod', 'From unrestricted, through sensible defaults, to hardened.'],
    ['security', 'What replaced PodSecurityPolicy?', 'Pod Security Admission', 'NetworkPolicy', 'RBAC', 'Nothing', 'PodSecurityPolicy was removed in version 1.25. Pod Security Admission enforces the standards per namespace.'],
    ['security', 'What does runAsNonRoot: true do?', 'Refuses to start a container that would run as root', 'Removes the root user from the image', 'Makes the filesystem read-only', 'Encrypts the container', 'The kubelet checks the user the container would run as and will not start it as UID 0.'],
    ['security', 'What does readOnlyRootFilesystem: true protect against?', 'Changes to the container\'s own files while it runs', 'Reading Secrets', 'Network attacks', 'Running as root', 'With a read-only root, an attacker cannot drop files into the image\'s filesystem.'],
    ['security', 'In which order does a request pass the API server\'s checks?', 'Authentication, then authorization, then admission', 'Admission, then authentication, then authorization', 'Authorization, then admission, then authentication', 'All three at once', 'Who are you, may you do this, and then admission controllers may change or reject it.'],
    ['security', 'What is the principle of least privilege?', 'Grant only the permissions a task needs', 'Give everybody admin and audit later', 'Use one account for everything', 'Deny all access', 'Smaller grants mean a mistake or a stolen credential can do less.'],
    ['security', 'Why turn off automountServiceAccountToken for a pod that never calls the API?', 'So a break-in does not find a usable token inside', 'To make it start faster', 'To save memory', 'To give it a new IP', 'A token mounted for no reason is a credential waiting to be stolen.'],
    ['security', 'What is a mutating admission webhook allowed to do?', 'Change an object before it is stored', 'Only reject objects', 'Read Secrets from etcd', 'Restart nodes', 'Mutating webhooks run first and may alter the object. Validating ones then accept or reject.'],
    ['security', 'What does dropping Linux capabilities from a container do?', 'Removes kernel privileges it does not need', 'Removes CPU from it', 'Blocks all its network', 'Deletes its image layers', 'capabilities: drop: ["ALL"] and adding back only what is needed is a common hardening.'],
    ['security', 'Why pin an image by digest rather than by tag?', 'A digest always names the same content; a tag can be moved', 'A digest is shorter', 'Tags are not allowed in production', 'Digests pull faster', 'image@sha256:... is immutable. A tag such as latest can point somewhere new tomorrow.'],
    ['security', 'What can a RoleBinding to a ClusterRole grant?', 'That ClusterRole\'s permissions, inside the binding\'s namespace only', 'Cluster-wide access', 'Nothing: it is invalid', 'Access to nodes', 'It is how one ClusterRole, such as view, is reused namespace by namespace.'],

    // ── trouble: finding out what is wrong ──────────────────────────────
    ['trouble', 'What does CrashLoopBackOff mean?', 'The container keeps exiting and is restarted with a growing delay', 'The image cannot be pulled', 'No node has room for the pod', 'The pod was evicted', 'It starts, exits, and the kubelet waits longer each time before trying again.'],
    ['trouble', 'How long can the delay of a crash loop grow to?', 'Five minutes', 'Ten seconds', 'One hour', 'It has no limit', 'The backoff doubles from ten seconds up to a cap of five minutes.'],
    ['trouble', 'A container shows OOMKilled. What happened?', 'It used more memory than its limit', 'It used too much CPU', 'Its disk was full', 'Its image was missing', 'The kernel killed it for exceeding its memory limit. Its exit code is 137.'],
    ['trouble', 'A pod is stuck in ImagePullBackOff. What is the cause?', 'The image cannot be pulled: wrong name, missing tag or no credentials', 'The container keeps crashing', 'The node is out of memory', 'A probe is failing', 'Check the image name and tag, and the pull secret for a private registry.'],
    ['trouble', 'A pod stays Pending with the reason Unschedulable. What does it need?', 'A node it fits on', 'A new image', 'More replicas', 'A restart', 'No node satisfies its requests, selectors, taints or affinity. kubectl describe names which.'],
    ['trouble', 'Which command shows why a pod is not starting, with its events?', 'kubectl describe pod', 'kubectl get pod -o name', 'kubectl top pod', 'kubectl version', 'describe ends with the pod\'s events: scheduling, pulling, probes failing.'],
    ['trouble', 'How do you read the log of a container\'s previous run, after a crash?', 'kubectl logs --previous', 'kubectl logs --old', 'kubectl describe --last', 'kubectl history', '--previous (or -p) shows what the container wrote before it was restarted.'],
    ['trouble', 'What happens when a liveness probe keeps failing?', 'The container is restarted', 'The pod is removed from its Service', 'The node is cordoned', 'Nothing', 'Liveness asks whether it is alive. Failing it means a restart.'],
    ['trouble', 'What happens when a readiness probe fails?', 'The pod stops receiving traffic from its Services', 'The container is restarted', 'The pod is deleted', 'The Deployment is rolled back', 'Readiness asks whether it can serve. It is taken out of the endpoints and left running.'],
    ['trouble', 'What is a startup probe for?', 'Giving a slow-starting container time before the other probes begin', 'Checking the node at boot', 'Pulling the image', 'Starting the kubelet', 'Until it succeeds, liveness and readiness are held off, so a slow start is not killed.'],
    ['trouble', 'Is CrashLoopBackOff one of a pod\'s phases?', 'No: the phases are Pending, Running, Succeeded, Failed and Unknown', 'Yes', 'Only for Jobs', 'Only on Linux nodes', 'It is a container\'s waiting reason. A pod in a crash loop is in phase Running.'],
    ['trouble', 'What does kubectl top need in order to work?', 'A metrics server', 'An ingress controller', 'A service mesh', 'Helm', 'It reads the resource metrics API, which metrics-server provides.'],
    ['trouble', 'What usually causes a pod to be Evicted?', 'Its node ran short of memory or disk', 'Its image was deleted', 'A user ran kubectl logs', 'A Service was removed', 'Under node pressure the kubelet evicts pods to protect the node.'],
    ['trouble', 'A node shows NotReady. What does that mean?', 'Its kubelet has stopped reporting healthy', 'It has no pods', 'It is being upgraded', 'It is the control plane', 'The control plane has not heard a healthy status from that node\'s kubelet.'],
    ['trouble', 'A pod is stuck Terminating for a long time. What often holds it?', 'A finalizer that has not been cleared', 'A full disk on your laptop', 'A missing label', 'Too many replicas', 'An object is kept until each of its finalizers is removed by whatever owns it.'],
    ['trouble', 'How do you open a shell in a running container?', 'kubectl exec -it pod -- sh', 'kubectl ssh pod', 'kubectl attach --shell', 'kubectl run --inside', 'exec runs a command in the container. -it gives it your terminal.'],
    ['trouble', 'What is kubectl debug used for?', 'Adding a temporary container to a pod to investigate it', 'Printing the API server\'s source', 'Turning on verbose logs', 'Rebooting a node', 'An ephemeral container brings tools into a pod whose own image has none.'],
    ['trouble', 'Exit code 137 means the container was ended by which signal?', 'SIGKILL', 'SIGTERM', 'SIGHUP', 'SIGINT', '137 is 128 plus 9, and signal 9 is SIGKILL. An out-of-memory kill looks like this.'],

    // ── sched: where pods land, and how much they get ───────────────────
    ['sched', 'What is the difference between a request and a limit?', 'A request is what a container is guaranteed, a limit is the most it may use', 'They are the same', 'A request is for memory, a limit for CPU', 'A limit is advice only', 'The scheduler places pods by their requests. Limits are enforced while they run.'],
    ['sched', 'What happens when a container goes over its CPU limit?', 'It is throttled', 'It is killed', 'Its pod is evicted', 'Its node is drained', 'CPU can be held back. Memory cannot, which is why going over a memory limit is a kill.'],
    ['sched', 'What are the three quality-of-service classes?', 'Guaranteed, Burstable and BestEffort', 'Gold, Silver and Bronze', 'High, Medium and Low', 'Fast, Slow and Idle', 'They are derived from requests and limits, and decide who is evicted first.'],
    ['sched', 'Which pods are in the Guaranteed class?', 'Those whose every container has requests equal to its limits', 'Those with no limits at all', 'Those in kube-system', 'Those with a PriorityClass', 'Equal CPU and memory requests and limits on every container.'],
    ['sched', 'What does the HorizontalPodAutoscaler change?', 'The number of pods', 'The size of each pod', 'The number of nodes', 'The image version', 'It adds or removes replicas to hold a metric, such as CPU, near a target.'],
    ['sched', 'What does the Cluster Autoscaler add when pods cannot be scheduled?', 'Nodes', 'Replicas', 'Namespaces', 'Memory to a pod', 'It grows a node group for Pending pods, and shrinks it when nodes sit empty.'],
    ['sched', 'What does a taint on a node do?', 'Keeps away pods that do not tolerate it', 'Attracts pods with the same label', 'Marks the node for deletion', 'Encrypts the node', 'A taint repels. A matching toleration on the pod lets it land there.'],
    ['sched', 'Which is NOT a taint effect?', 'NoRestart', 'NoSchedule', 'PreferNoSchedule', 'NoExecute', 'The three are NoSchedule, PreferNoSchedule and NoExecute.'],
    ['sched', 'What does kubectl cordon do to a node?', 'Stops new pods being scheduled there, and leaves running ones', 'Deletes every pod on it', 'Reboots it', 'Removes it from the cluster', 'Cordon marks it unschedulable. Drain also evicts what is running.'],
    ['sched', 'What does kubectl drain do?', 'Cordons the node and evicts its pods', 'Empties the node\'s disk', 'Removes its taints', 'Deletes its volumes', 'It is how a node is emptied before maintenance.'],
    ['sched', 'What does a PodDisruptionBudget protect against?', 'Too many pods going down at once in a voluntary disruption', 'Running out of budget in the cloud', 'Memory leaks', 'Slow image pulls', 'A drain respects the budget, so an application keeps a minimum of pods.'],
    ['sched', 'How do you keep two replicas off the same node?', 'Pod anti-affinity', 'A NodePort', 'A larger limit', 'A ConfigMap', 'Anti-affinity tells the scheduler not to place a pod beside pods it matches.'],
    ['sched', 'What does a ResourceQuota limit?', 'The total resources a namespace may use', 'One container\'s memory', 'The number of nodes', 'The size of an image', 'A quota caps a namespace as a whole. A LimitRange sets per-container defaults and bounds.'],
    ['sched', 'A pod has no requests or limits at all. Which class is it?', 'BestEffort', 'Guaranteed', 'Burstable', 'Unbounded', 'BestEffort pods are the first to be evicted when a node is under pressure.'],
    ['sched', 'What is 500m of CPU?', 'Half a core', 'Five hundred cores', '500 megabytes', 'Five cores', 'm is millicores: 1000m is one core.'],
    ['sched', 'What does a PriorityClass let a pod do?', 'Be scheduled ahead of, and even displace, lower-priority pods', 'Use more memory than its limit', 'Skip its probes', 'Run on the control plane', 'When there is no room, the scheduler can preempt lower-priority pods for it.'],
    ['sched', 'What does the VerticalPodAutoscaler adjust?', 'A pod\'s requests', 'The number of replicas', 'The number of nodes', 'The pod\'s image', 'It recommends or sets CPU and memory requests from what the pod really uses.'],

    // ── quality: shipping it safely ─────────────────────────────────────
    ['quality', 'When a pod is deleted, what does its container receive first?', 'SIGTERM, and time to stop', 'SIGKILL at once', 'Nothing', 'A new IP address', 'It is sent SIGTERM, and SIGKILL only if it is still running when the grace period ends.'],
    ['quality', 'What is the default termination grace period?', '30 seconds', '5 seconds', '5 minutes', 'There is none', 'terminationGracePeriodSeconds defaults to 30.'],
    ['quality', 'What is a preStop hook for?', 'Running something before the container is told to stop', 'Checking the image before it starts', 'Stopping the node', 'Skipping the grace period', 'It lets an application finish in-flight work before SIGTERM arrives.'],
    ['quality', 'Which command waits for a rollout to finish and reports if it fails?', 'kubectl rollout status', 'kubectl get rollout', 'kubectl wait deploy', 'kubectl logs rollout', 'kubectl rollout status deployment/name follows it to the end.'],
    ['quality', 'What does a canary release do?', 'Sends a small share of traffic to the new version first', 'Replaces every pod at once', 'Runs tests on a laptop', 'Deletes the old version first', 'A few users meet the new version, and it is widened only if it behaves.'],
    ['quality', 'What is a blue-green deployment?', 'Two full environments, with traffic switched from one to the other', 'A deployment with two containers', 'Two namespaces with the same name', 'A rolling update with colours', 'The new version runs beside the old, and the switch is a change of where traffic goes.'],
    ['quality', 'What does --dry-run=server do?', 'Sends the request through validation and admission without saving it', 'Runs the pod once and deletes it', 'Tests the network', 'Prints the kubeconfig', 'The API server checks it fully and stores nothing.'],
    ['quality', 'What does kubectl diff show?', 'What applying a file would change in the cluster', 'The difference between two nodes', 'Which pods restarted', 'Two versions of kubectl', 'It compares your file with the live object before you apply.'],
    ['quality', 'An image is tagged latest. What is its default pull policy?', 'Always', 'IfNotPresent', 'Never', 'Weekly', 'With latest or no tag the default is Always. With any other tag it is IfNotPresent.'],
    ['quality', 'How many times does a Job retry by default before it is marked failed?', 'Six', 'Once', 'Three', 'For ever', 'backoffLimit defaults to 6.'],
    ['quality', 'What does a Job\'s completions field set?', 'How many pods must finish successfully', 'How many may run at once', 'How long it may run', 'How many nodes it uses', 'completions is how many successes. parallelism is how many run at a time.'],
    ['quality', 'A CronJob\'s concurrencyPolicy is Forbid. What happens if the last run is still going?', 'The new run is skipped', 'Both run together', 'The old run is killed', 'The CronJob is deleted', 'Forbid skips. Replace stops the old one. Allow, the default, runs both.'],
    ['quality', 'What does minReadySeconds add to a rollout?', 'A time a new pod must stay ready before it counts as available', 'A delay before pulling images', 'A minimum pod lifetime', 'A timeout for probes', 'It slows a rollout so that a pod which fails soon after starting is caught.'],
    ['quality', 'In a rolling update, what does maxUnavailable set?', 'How many pods may be missing during the update', 'How many extra pods may exist', 'How many nodes may be down', 'How many updates may run', 'With maxUnavailable 0, capacity never drops during a rollout.'],
    ['quality', 'What are annotations for?', 'Attaching information that is not used to select objects', 'Selecting pods for a Service', 'Naming containers', 'Setting resource limits', 'Tools read annotations. Selectors only ever match labels.'],
    ['quality', 'How many fields does a CronJob schedule have?', 'Five: minute, hour, day of month, month, day of week', 'Three', 'Six, with seconds', 'One', 'It is standard cron: "0 3 * * *" is three in the morning every day.'],
    ['quality', 'A Deployment\'s new pods never become ready. What does the rolling update do?', 'Stalls, with old pods still serving', 'Deletes all the old pods anyway', 'Rolls back by itself at once', 'Deletes the Deployment', 'It removes old pods only as far as maxUnavailable allows, so it stalls and most of the old version keeps serving until you fix or undo it.']
  ];

  /* Who stands in the street. `hero` is the figure it is drawn as (the same
     eight you may choose to be), `subjects` what it asks about, and `gift`
     what it gives the first time you answer it rightly. */
  var EXPERTS = [
    { key: 'devops', hero: 0, role: 'DevOps engineer', subjects: ['workloads'], hello: 'It works on my cluster. Let us see if it works on yours.', gift: 'drone', has: 'a deploy drone that follows you' },
    { key: 'sec', hero: 1, role: 'DevSecOps engineer', subjects: ['security'], hello: 'I trust nobody. You may still ask.', gift: 'shield', has: 'a shield of light' },
    { key: 'noc', hero: 2, role: 'NOC engineer', subjects: ['trouble'], hello: 'I have seen things at three in the morning. Ask me what is on fire.', gift: 'radar', has: 'a line on the ground to whoever needs help most' },
    { key: 'net', hero: 3, role: 'Network engineer', subjects: ['network'], hello: 'It is never DNS. It was DNS.', gift: 'trail', has: 'a trail of light behind you' },
    { key: 'ceo', hero: 4, role: 'CEO', subjects: ['basics'], hello: 'Can we have it by Friday? Also: what is a pod?', gift: 'crown', has: 'a golden crown' },
    { key: 'pm', hero: 5, role: 'Project manager', subjects: ['sched'], hello: 'Just a quick sync. It will only take a question.', gift: 'confetti', has: 'a confetti cannon: press B' },
    { key: 'qa', hero: 6, role: 'QA engineer', subjects: ['quality'], hello: 'Works as designed? Prove it.', gift: 'bug', has: 'a pet bug that follows you' },
    { key: 'dba', hero: 7, role: 'DBA', subjects: ['storage'], hello: 'Who ran that query in production? Never mind. Ask.', gift: 'coffee', has: 'a strong coffee: you walk a fifth faster' }
  ];
  var SUBJECTS = { basics: 'the basics', workloads: 'workloads and rollouts', network: 'networking', storage: 'storage and etcd', security: 'security', trouble: 'troubleshooting', sched: 'scheduling and resources', quality: 'releasing safely' };

  function plural(n, w) { return n + ' ' + w + (n === 1 ? '' : 's'); }
  function sick(b) { return b.state === 'bad'; }
  function unready(b) { return b.nodes ? b.nodes.total - b.nodes.ready : 0; }
  function known(bs) { return (bs || []).filter(function (b) { return b.pods; }); }
  function most(list, value) {      // the one with the highest value, or null when two share it: a tie has no right answer
    var best = null, top = -1, tie = false;
    list.forEach(function (b) { var v = value(b); if (v > top) { top = v; best = b; tie = false; } else if (v === top) tie = true; });
    return tie || !best ? null : best;
  }

  /* Questions about YOUR clusters, made from what the city knows this minute.
     Each is asked only when it has one right answer: with two clusters level,
     or none failing, the question is not put. Clusters that did not answer or
     are not read yet are never the answer and never a wrong option, because
     nothing is known about them. */
  function live(d) {
    var bs = known(d && d.buildings), bad = bs.filter(sick), out = [], top;
    function names(right, pool) {
      var rest = pool.filter(function (b) { return b !== right; }).slice(0, 3).map(function (b) { return b.name; });
      return rest.length >= 2 ? [right.name].concat(rest) : null;
    }
    function ask(text, right, pool, why) { var o = right && names(right, pool); if (o) out.push({ id: 'live:' + text, subject: 'live', q: text, options: o, why: why }); }
    top = most(bs, function (b) { return b.pods.total; });
    ask('Which of our clusters runs the most pods right now?', top, bs, top && top.name + ' runs ' + plural(top.pods.total, 'pod') + ', more than any other that answered.');
    top = most(bs, function (b) { return b.nodes.total; });
    ask('Which of our clusters has the most machines?', top, bs, top && top.name + ' has ' + plural(top.nodes.total, 'machine') + '.');
    top = bad.length ? most(bs, function (b) { return b.pods.bad; }) : null;
    ask('Which of our clusters has the most failing pods right now?', top, bs, top && top.name + ' has ' + plural(top.pods.bad, 'pod') + ' failing.');
    top = most(bs.filter(function (b) { return b.cpu != null; }), function (b) { return b.cpu; });
    ask('Which of our clusters is using the most of its CPU?', top, bs.filter(function (b) { return b.cpu != null; }), top && top.name + ' is at ' + Math.round(top.cpu) + '% of its CPU.');
    return out;
  }
  /* A bank question, as it is asked: `options[0]` is the right one until it is shuffled. */
  function fromBank(i) { var q = Q[i]; return { id: 'q' + i, subject: q[0], q: q[1], options: [q[2], q[3], q[4], q[5]], why: q[6] }; }
  /* The next question an expert asks: one of its own subjects that you have
     not been asked yet, and now and then one about your own clusters. When
     its subjects are used up it starts them again. `seen` is the ids already
     asked and is added to; `rnd` is a number from 0 to 1. */
  function next(expert, seen, d, rnd) {
    var mine = [], fresh, pool, own = live(d), pick;
    Q.forEach(function (q, i) { if (expert.subjects.indexOf(q[0]) >= 0) mine.push(i); });
    if (own.length && rnd() < 0.2) return shuffled(own[Math.floor(rnd() * own.length)], rnd);
    fresh = mine.filter(function (i) { return seen.indexOf('q' + i) < 0; });
    if (!fresh.length) { mine.forEach(function (i) { var at = seen.indexOf('q' + i); if (at >= 0) seen.splice(at, 1); }); fresh = mine; }
    pool = fresh; pick = fromBank(pool[Math.floor(rnd() * pool.length)]);
    seen.push(pick.id);
    return shuffled(pick, rnd);
  }
  function shuffled(q, rnd) {
    var right = q.options[0], o = q.options.slice(), i, j, t;
    for (i = o.length - 1; i > 0; i--) { j = Math.floor(rnd() * (i + 1)); t = o[i]; o[i] = o[j]; o[j] = t; }
    return { id: q.id, subject: q.subject, q: q.q, options: o, right: o.indexOf(right), why: q.why };
  }
  /* What an expert says of the clusters. Each looks at the same facts from
     its own chair, and none says all is well while a cluster is unread or
     silent: it says what it does not know. */
  function brief(expert, d) {
    var all = (d && d.buildings) || [], bs = known(all), bad = bs.filter(sick), down = all.filter(function (b) { return b.state === 'down'; }),
      reading = all.filter(function (b) { return b.state === 'reading'; }), t = (d && d.totals) || {}, k = expert.key, top, parts = [], tally = {}, unknown;
    unknown = (down.length ? ' ' + plural(down.length, 'cluster') + ' did not answer, so I cannot speak for ' + (down.length === 1 ? 'it' : 'them') + '.' : '')
      + (reading.length ? ' ' + plural(reading.length, 'cluster') + (reading.length === 1 ? ' has' : ' have') + ' not been read yet.' : '');
    if (!all.length) return 'There is no cluster in this city yet. Add one on the Clusters page.';
    if (!bs.length) return 'I have nothing to go on:' + unknown;
    bad.sort(function (a, b) { return b.pods.bad - a.pods.bad || unready(b) - unready(a); });
    if (k === 'noc') return (bad.length ? plural(bad.length, 'cluster') + (bad.length === 1 ? ' needs' : ' need') + ' somebody: ' + bad.slice(0, 3).map(function (b) {
      return b.name + ' (' + (b.pods.bad ? plural(b.pods.bad, 'pod') + ' failing' : plural(unready(b), 'machine') + ' not ready') + ')'; }).join(', ') + '.' : 'Nothing is failing in the clusters that answered.') + unknown;
    if (k === 'devops') { top = most(bs, function (b) { return b.pods.total; });
      return plural(bs.length, 'cluster') + ' answered, running ' + plural(t.pods || 0, 'pod') + ' on ' + plural(t.nodes || 0, 'machine') + '.' + (top ? ' The biggest is ' + top.name + ' with ' + plural(top.pods.total, 'pod') + '.' : '') + unknown; }
    if (k === 'sec') { top = all.filter(function (b) { return b.prod; });
      return (top.length ? plural(top.length, 'cluster') + (top.length === 1 ? ' serves' : ' serve') + ' production: ' + top.map(function (b) { return b.name + ' (' + (b.state === 'ok' ? 'well' : b.state === 'bad' ? 'needs help' : b.state === 'down' ? 'no signal' : 'not read') + ')'; }).join(', ') + '. Those ask for their name before anything is changed.'
        : 'No cluster here is marked as serving production.') + unknown; }
    if (k === 'net') return (down.length ? 'I cannot reach ' + down.map(function (b) { return b.name + ' (' + (b.why || 'it did not answer') + ')'; }).join('; ') + '.' : 'Every cluster I tried answered.') + (reading.length ? ' ' + plural(reading.length, 'cluster') + ' I have not tried yet.' : '');
    if (k === 'dba') { top = most(bs.filter(function (b) { return b.mem != null; }), function (b) { return b.mem; });
      return (top ? 'The fullest memory is in ' + top.name + ', at ' + Math.round(top.mem) + '%.' : 'No cluster gave me a memory figure I can rank.') + unknown; }
    if (k === 'qa') { bad.forEach(function (b) { b.problems.forEach(function (p) { tally[p.status || 'not well'] = (tally[p.status || 'not well'] || 0) + 1; }); });
      Object.keys(tally).sort(function (a, b) { return tally[b] - tally[a]; }).forEach(function (s) { parts.push(tally[s] + ' ' + s); });
      return (parts.length ? 'Of the failing pods I can name: ' + parts.join(', ') + '.' : bad.length ? 'Pods are failing, and none was named to me.' : 'No failing pod was reported to me.') + unknown; }
    if (k === 'pm') return (bs.length - bad.length) + ' of ' + plural(bs.length, 'cluster') + ' that answered ' + (bs.length - bad.length === 1 ? 'is' : 'are') + ' well, and ' + bad.length + (bad.length === 1 ? ' needs' : ' need') + ' help.' + unknown + ' I will put it in the status report.';
    return (bad.length || down.length || reading.length ? 'Not everything is fine: ' + bad.length + ' need help' + (down.length ? ', ' + down.length + ' silent' : '') + (reading.length ? ', ' + reading.length + ' unread' : '') + '.' : 'All ' + plural(bs.length, 'cluster') + ' are up. Good. Keep it that way.') + ' Now, about Friday.';
  }

  var api = { Q: Q, EXPERTS: EXPERTS, SUBJECTS: SUBJECTS, next: next, live: live, brief: brief, shuffled: shuffled, fromBank: fromBank };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof window !== 'undefined') window.C3DQuiz = api;
})();
