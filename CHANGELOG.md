# Changelog

All notable changes to Paguro. Versions follow [Semantic
Versioning](https://semver.org); before 1.0 a minor version may change the
API (`paguro.dev/v1alpha1`) and the chart's values.

## v0.1.2 – 2026-10-10

Fixed:

- Phantom mode: a connection whose pod comes back to a node and an address
  it held there before (the AWS VPC CNI hands a freed address out again)
  no longer hangs. The node still had the connection's conntrack entries
  from the pod's earlier stay, with old sequence numbers; window tracking
  rated every packet INVALID and kube-proxy dropped it, in both directions.
  Connections with little traffic stayed inside the old window and were
  not affected. The target node now deletes such entries – exactly the
  migrated flow's tuple, never one with NAT – before it translates.

Added:

- The README and the package page show recordings of a Minecraft Java
  Edition (TCP) and a Red Eclipse (UDP) server live-migrating on Amazon
  EKS: about 2 s per migration, 0.3–0.4 s frozen, players stay connected.

## v0.1.1 – 2026-10-09

Documentation only: the chart's README and its Artifact Hub page no longer
show the recording of a migration with a 25 GiB block volume, whose freeze
of about 12 s (the volume's detach and attach) is not typical. Install
commands point to 0.1.1. No code changes.

## v0.1.0 – 2026-10-09

First public release. Paguro live-migrates running Kubernetes pods between
nodes with CRIU: memory, open files, root filesystem changes, `emptyDir`s
and volumes move with the pod, and its TCP connections and UDP flows
continue – with the pod IP kept where the CNI can move it (Cilium, Calico)
and with Phantom mode everywhere else. The API is `paguro.dev/v1alpha1`
(alpha).

```
helm install paguro oci://ghcr.io/dpicillo/charts/paguro --version 0.1.0 \
  -n paguro-system --create-namespace
```

Installation: docs/INSTALL.md. The story behind Paguro:
https://www.picillo.de/blog/kubernetes-pod-live-migration/

### Migration

- `Migration` resource and the kubectl plugin (`kubectl paguro migrate`,
  `drain`, `list`, `describe`, `nodes`, `version`); workloads opt in with
  the pod label `paguro.dev/migratable: "true"`. The network mode is chosen
  per migration (`spec.network`) or per workload (annotation
  `paguro.dev/network`): `Auto`, `Preserve`, `Phantom` or `Generic`; an
  unknown value is refused, never read as `Auto`.
- Pre-copy in rounds while the pod runs, with auto-converge (CPU
  throttling when the rounds would not reach the freeze budget); the final
  dump happens in a freeze that clients see as a short stall. A round that
  cannot freeze a process in uninterruptible I/O (NFS) starts over, twice
  at most, before the migration rolls back.
- A commit point: every failure before it rolls back and the source simply
  continues; after it the replacement is the workload (the restore is
  retried, a cold start is the last resort).
- Replacements for Deployments (created during pre-copy), StatefulSets,
  bare pods and other owners (under the same name), and Agones
  GameServers.
- Lazy restore for pods from 64 MiB on; CRIU patched for fast page faults
  on large, fragmented memory.
- A CPU baseline for migratable pods, so that they can move between CPU
  generations.
- Chained migrations: a pod moves again and again, also back to a node and
  an address it had before.

### Volumes and files

- RWO volumes detached and attached around the freeze, attached during
  pre-copy for multi-attach volume types (opt-in); RWX volumes written back
  before the final dump, file locks on shared filesystems handed over,
  files deleted while open on NFS migrated.
- `emptyDir`s copied during pre-copy; the freeze carries only what changed.
  The pod's own `/dev/shm` (the sandbox's tmpfs, not a volume) moves too.
- Container images pinned to the digest the source ran.

### Networking

- Pod IP kept on **Cilium** (multi-pool IPAM: a sticky /32 per pod, handed
  over early) and **Calico** (calico-ipam, with a route guard and a NAT
  guard for NodePort and LoadBalancer clients); every connection survives,
  also to peers outside the cluster.
- **Phantom mode** where the IP cannot move: the pod gets a new IP, and
  eBPF programs on the nodes involved translate the old address of each
  migrated in-cluster connection (TCP and UDP). Works with any CNI –
  Flannel, Antrea, the AWS VPC CNI and others. Connections it cannot keep
  are aborted right after the restore, so the application reconnects at
  once. A peer node routes the old address only for the migrated
  connections, so an address the CNI hands to another pod reaches its new
  owner – at a cost per packet that does not grow with their number: the
  forwarded ones (pods behind a ClusterIP, NodePort clients) are selected by
  one bit of the packet mark (`phantom.steeringMark`, default `0x2000`) and
  a single policy rule, not by a rule each.
- UDP servers that know their players by address keep them when the pod
  gets a new IP, also players behind a NodePort or LoadBalancer whose
  source port the node masquerades with `--random-fully` (measured on
  Amazon EKS with real Xonotic and Red Eclipse clients behind an NLB: no
  session lost in 37 migrations).
- Services keep the migrating pod as an endpoint until its replacement
  serves – with a kept and with a new IP – so new connections during a
  migration are delayed, not refused; the replacement's readiness probe
  starts without its initial delay. In Phantom mode a connection opened
  through a Service during the freeze is handed back to the Service after
  the restore instead of hanging until the client's timeout.
- Commit gate (Dynamic Resource Allocation, Kubernetes ≥ 1.34): with a kept
  IP the replacement's sandbox is created the moment the migration
  commits.

### Drains, autoscalers and spot

- Evictions of migratable pods become migrations: `kubectl drain`,
  Karpenter (drift, consolidation, expiry, spot interruptions), the
  Cluster Autoscaler and managed node group upgrades move such pods
  instead of restarting them. A migration that fails lets the next
  eviction through.
- At most three migrations leave a node at a time
  (`controller.migrationsPerNode`); an eviction's migration waits up to two
  minutes for a node to move to (`controller.evictionTargetWait`) – the
  one Karpenter launches.
- On EC2 a spot interruption's deadline (`paguro.dev/terminates-at`)
  decides whether a migration still fits; otherwise the eviction goes
  through at once.
- Startup taint `paguro.dev/agent-not-ready` for Karpenter NodePools: new
  nodes count as initialized once Paguro's agent runs there.

### Security

- Mutual TLS 1.3 between agents with a certificate per node, signed by the
  controller only for the requester's own node; a target takes a
  migration's data only from its source node.
- Admission policies hold each agent's service account to its own node
  (Kubernetes ≥ 1.30).
- Checkpoints are removed after every migration, and by a janitor.
- Images and chart signed with cosign (keyless), SPDX SBOM attestations,
  govulncheck and grype on every release. Threat model: SECURITY.md.

### Operations

- One Helm chart; its node installer prepares containerd, CRIU and
  nftables on every node and undoes exactly its changes on uninstall.
- Upgrades during running migrations: a stopping agent first finishes the
  migrations on its node, and only agents of the same release migrate
  between each other.
- Prometheus metrics, alert rules, PodMonitors and a Grafana dashboard
  (docs/OPERATIONS.md).
- The agent requests 200m CPU: its weight on a busy node, where CRIU and
  the compression of the pre-copy run in its cgroup
  (`agent.resources.requests.cpu`; raise it for busy nodes and large pods).

### Tested with

- Kubernetes 1.28–1.37: install, webhook, CRD validation, preflight,
  admission policies, commit gate and agent certificates on kind for every
  minor version; migrations on 1.37.
- kubeadm clusters with Cilium, Calico, Flannel and Antrea; containerd
  2.0, 2.1 and 2.4; Ubuntu 22.04 and 24.04, Debian 12, Amazon Linux 2023.
- Amazon EKS 1.37 with Amazon Linux 2023 nodes, the AWS VPC CNI and
  Karpenter 1.14 (drift, NodeClaim deletion, spot interruption warnings).
- Agones 1.61.

Freezes measured: 0.55–0.73 s with the IP kept on Cilium, 1.23–1.58 s on
Calico, 0.3–0.9 s in Phantom mode (small pods, kubeadm lab); on EKS,
Minecraft Java and Bedrock servers with eight players each 0.44–0.66 s,
no player disconnected. More in the README and docs/CNI.md.

### Known limitations

- Phantom mode keeps in-cluster connections only: peers outside the
  cluster – on the AWS VPC CNI also NLB/ALB IP targets and other EC2
  instances that reach the pod IP – are closed cleanly.
- Phantom mode: when the restore fails and the replacement cold-starts,
  the in-cluster peers' connections are aborted at once; clients outside
  the cluster (through a NodePort or LoadBalancer) wait for their own
  timeout.
- Phantom mode: a connection opened through a Service during the freeze
  completes about 3 s after the attempt (with a later SYN
  retransmission), and one opened to the old pod IP itself is not
  translated; UDP clients that write to the pod IP directly (not through a
  Service) lose the session; workloads that hand out their own pod IP
  (Kafka `advertised.listeners`, peer URLs) need a CNI that keeps the IP.
- Players connected through an Agones host port lose the connection (the
  node's address changes).
- Containers with stdin or a TTY are refused (every GitLab Runner job pod);
  processes of `kubectl exec` sessions do not survive a migration.
- A unix socket connection that is not accepted yet and already holds data
  fails CRIU's final dump; the migration rolls back (GitLab under load).
- A lazy restore can fail in CRIU's restorer with `vdso: Invalid ELF
  magic` (GitLab's runit processes on EKS after 5–10 pre-copy rounds; not
  reproduced with the same processes in small pods). The restore wrapper
  then tries once more without lazy pages before it falls back to a cold
  start; the cause is not found yet.
- Memory written nearly as fast as the network copies it gives long
  freezes (8 GiB rewritten at 50 MB/s over 1 GbE: 21–33 s).
- An RWO block volume adds its detach to the freeze (6–9 s on Cinder); EBS
  volumes move only within their availability zone.
- A spot interruption leaves two minutes; a migration that does not fit
  lets the eviction through. In one of five spot runs on EKS the players
  lost the connection about 20 s after a successful restore (not
  reproduced since).
- Not supported: arm64 (not yet), Bottlerocket, EKS Auto Mode, Fargate,
  Windows, CRI-O and Docker. Not run yet: GKE, AKS, service meshes,
  Calico's eBPF dataplane, clusters of more than five nodes.

### Upgrading

First release – nothing to upgrade from. Before 1.0 a minor version may
change the API and the chart's values; each release's notes say what to
do.
