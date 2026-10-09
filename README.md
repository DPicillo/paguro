# Paguro

<img src="docs/images/paguro.svg" alt="Paguro logo: a hermit crab carrying its shell" width="112" align="right">

[![CI](https://github.com/DPicillo/paguro/actions/workflows/ci.yaml/badge.svg)](https://github.com/DPicillo/paguro/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/DPicillo/paguro?sort=semver)](https://github.com/DPicillo/paguro/releases)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/paguro)](https://artifacthub.io/packages/search?repo=paguro)
[![License: AGPL-3.0-only](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

**Kubernetes pod live migration, built on CRIU.** Paguro moves running pods
between nodes – their memory, open files, volumes and network connections –
and resumes them there. Clients see a stall of well under a second, not a
restart: zero-downtime drains, node upgrades and spot replacements.

It is made for workloads that cannot simply be restarted or failed over:
game servers with players connected, long-running jobs, sessions held in
memory, single-replica services. Because Paguro answers the Eviction API,
`kubectl drain`, Karpenter and the Cluster Autoscaler move such pods
instead of killing them.

> **Read the story behind Paguro:
> [Kubernetes pod live migration](https://www.picillo.de/blog/kubernetes-pod-live-migration/)**

> **Status: alpha (v0.1).** The API is `paguro.dev/v1alpha1` and may change
> between minor versions. Read the [known limitations](#known-limitations)
> before you rely on it.

*Paguro* is Italian for hermit crab – an animal that moves house.

## What it does

- Moves a running pod between nodes with [CRIU](https://criu.org):
  process memory, open files, root filesystem changes, `emptyDir`s and
  PersistentVolumeClaims (RWO volumes are re-attached, RWX volumes written
  back).
- Keeps the pod's TCP connections and UDP flows. Where the CNI can move an
  address (Cilium with multi-pool IPAM, Calico) the pod keeps its IP;
  elsewhere it gets a new IP and **Phantom mode** keeps its in-cluster
  connections alive by eBPF translation.
- Turns evictions of migratable pods into migrations: `kubectl drain`,
  Karpenter (drift, consolidation, spot interruptions), the Cluster
  Autoscaler, managed node group upgrades – no integration with each of
  them needed.
- Moves Agones GameServers with their game state; they stay `Allocated`.
- Rolls back safely: until the commit point any failure leaves the source
  pod running as if nothing happened.
- Installs with one Helm chart. A node installer prepares containerd, CRIU
  and nftables on every node; no CNI fork and no cloud API calls to move
  addresses.

## What it does not do

- **It is not a high-availability mechanism.** A migration needs the
  source node and its agent alive: planned moves, drains, upgrades,
  consolidation and spot interruption *warnings* – not a node that crashed
  or vanished.
- It does not move pods between clusters, or between CPU architectures
  (amd64 ↔ arm64).
- It does not move data that belongs to a node: `hostPath` volumes and
  local PersistentVolumes are refused by the preflight (`emptyDir`s do
  move, with their content).
- It does not run on CRI-O, Docker, Windows, Fargate, Bottlerocket or EKS
  Auto Mode nodes.

## How it works

1. **Opt in per workload.** Label the pod template
   `paguro.dev/migratable: "true"`. Paguro's webhook gives such pods the
   RuntimeClass `paguro` (an own time namespace, so monotonic clocks keep
   running after a move; Multipath TCP off, which CRIU cannot checkpoint), a
   CPU baseline, so they can move between CPU generations, and on Cilium a
   sticky IP.
2. **Pre-copy.** The source node's agent checkpoints the pod with CRIU in
   rounds while it keeps running (soft-dirty page tracking) and streams the
   pages, root filesystem changes and `emptyDir`s to the target node's
   agent over mutual TLS. If the pod writes memory faster than the network
   copies it, auto-converge throttles its CPU.
3. **Freeze and commit.** New connection attempts are dropped (clients
   retry them), the pod is paused, and CRIU dumps what changed since the
   last round, including the TCP state of every connection. One status
   update is the commit point: before it every failure rolls back and the
   source thaws; after it the replacement is the workload (the restore is
   retried, a cold start is the last resort).
4. **Restore.** The pod's owner – Deployment, StatefulSet, Agones, … –
   gets its replacement on the target node. Paguro's runtime wrapper
   `paguro-runc` turns `runc create` into `runc restore`, so kubelet and
   containerd see an ordinary container start. Large pods are restored
   lazily: memory arrives as the process touches it.
5. **Network.** `Auto` keeps the pod IP where the CNI can move it – then
   every connection survives, including peers outside the cluster.
   Elsewhere it uses Phantom mode: the pod gets a new IP, and eBPF programs
   on the nodes involved translate the old address of exactly the migrated
   in-cluster connections ([PHANTOM-MODE.md](docs/PHANTOM-MODE.md)).
6. **Volumes.** RWO volumes are detached and attached around the freeze
   (attached during pre-copy for multi-attach volume types), RWX volumes
   are written back before the final dump and their file locks handed
   over, and container images are pinned to the digest the source ran.
7. **Evictions become migrations.** An admission webhook on
   `pods/eviction` answers the eviction of a migratable pod with "retry
   later" (HTTP 429) and migrates it; the drain goes on once the pod has
   moved. At most three migrations leave a node at a time, a migration
   waits up to two minutes for the node Karpenter launches, and on EC2 the
   spot interruption's deadline decides whether a move still fits.

The network mode is chosen per migration (`spec.network`, `kubectl paguro
migrate --network`) or per workload (pod annotation `paguro.dev/network`):

| Mode | Pod IP | Connections | Works with |
|---|---|---|---|
| `Auto` (default) | kept where possible | – | picks `Preserve`, else `Phantom`, else `Generic` |
| `Preserve` | kept | every TCP connection and UDP flow, also to peers outside the cluster | Cilium (multi-pool IPAM), Calico (calico-ipam) |
| `Phantom` | new | in-cluster TCP and UDP kept by eBPF translation; peers outside the cluster are closed cleanly | any CNI (needs bpffs; TCX hooks on kernel 6.6+, tc clsact before) |
| `Generic` | new | not kept: aborted right after the restore, so the application gets an error and reconnects at once instead of hanging | any CNI, also where Phantom mode cannot run |

Memory, open files, `emptyDir`s and volumes move in every mode. Details:
[ARCHITECTURE.md](docs/ARCHITECTURE.md), [CNI.md](docs/CNI.md).

## Quick start

### Requirements

| | |
|---|---|
| Kubernetes | 1.28 or later (1.30 for the agents' admission policies, 1.34 for the commit gate) |
| Nodes | Linux x86_64, real VMs or bare metal (kind nodes cannot checkpoint) |
| Kernel | 5.15 or later with `CONFIG_CHECKPOINT_RESTORE`; `CONFIG_MEM_SOFT_DIRTY` for pre-copy; time namespaces (`CONFIG_TIME_NS`) recommended |
| cgroups | v2 (unified hierarchy) |
| Container runtime | containerd 2.0 or later, runc 1.2 or later |
| CRIU | 4.0 or later – the node installer ships CRIU 4.2.1 when the host has none |
| Pod Security | the release namespace must allow privileged pods |

The node installer checks every node and reports what is missing; a node
that does not qualify is left alone. Full list:
[INSTALL.md](docs/INSTALL.md#requirements).

### Install

```sh
helm install paguro oci://ghcr.io/dpicillo/charts/paguro --version 0.1.0 \
  --namespace paguro-system --create-namespace
kubectl -n paguro-system rollout status ds/paguro-agent
```

If your cluster enforces a Pod Security standard by default, label the
namespace first:
`kubectl label ns paguro-system pod-security.kubernetes.io/enforce=privileged`.
Amazon EKS, Karpenter and on-premises specifics:
[INSTALL.md](docs/INSTALL.md). Every value of the chart, example values
(EKS with Karpenter, Cilium, Calico) and a usage guide:
[the chart's README](deploy/helm/paguro/README.md), also on
[Artifact Hub](https://artifacthub.io/packages/search?repo=paguro).

### Install the kubectl plugin

From the [GitHub release](https://github.com/DPicillo/paguro/releases)
(archives for Linux, macOS and Windows, and a checksum file):

```sh
VERSION=v0.1.0 OS=linux ARCH=amd64   # darwin, windows; arm64
curl -fsSLO https://github.com/DPicillo/paguro/releases/download/$VERSION/kubectl-paguro_${VERSION}_${OS}_${ARCH}.tar.gz
tar -xzf kubectl-paguro_${VERSION}_${OS}_${ARCH}.tar.gz
install -m 0755 kubectl-paguro_${VERSION}_${OS}_${ARCH}/kubectl-paguro ~/.local/bin/
kubectl paguro version   # the plugin's, the controller's and the agents' versions
kubectl paguro nodes     # agents, CRIU and CPU compatibility per node
```

Once the plugin is listed in the krew index: `kubectl krew install paguro`.

### Migrate a pod

Mark a workload as migratable – the label must be on the pod template and
takes effect for pods created after it:

```yaml
spec:
  template:
    metadata:
      labels:
        paguro.dev/migratable: "true"
```

Then move one of its pods, or drain a node:

```sh
kubectl paguro migrate <pod> -n <namespace> --wait   # Paguro picks the target
kubectl paguro migrate <pod> -n <namespace> --to <node> --wait
kubectl drain <node> --ignore-daemonsets             # migratable pods migrate
kubectl paguro list -A
```

Or create a `Migration` yourself:

```yaml
apiVersion: paguro.dev/v1alpha1
kind: Migration
metadata:
  name: move-game-server
  namespace: games
spec:
  podName: game-server-7d9f8-x2k4p
  # targetNode: node-b    # optional
  # network: Auto         # Auto | Preserve | Phantom | Generic
```

## Support matrix

What has been run, and how. "Not run" means not tested, not "known not to
work" – unless it says "not supported".

| Area | Status |
|---|---|
| Kubernetes | 1.28–1.37: installed and checked on kind for every minor version (install, webhook, CRD validation, preflight, admission policies, commit gate, agent certificates). Migrations run on 1.37 (kubeadm lab, Amazon EKS) |
| containerd | 2.0.7, 2.1.5, 2.4.1 (node installer tests); migrations on 2.4.1 and on EKS's Amazon Linux 2023 |
| Node OS | Ubuntu 22.04 and 24.04, Debian 12, Amazon Linux 2023 (bundled CRIU verified); the lab runs Ubuntu 24.04 |
| Architecture | x86_64. arm64: not yet (images are amd64 only; CRIU has no pre-copy there) |
| Distributions | kubeadm: tested. RKE2 and k3s: the node installer handles their containerd configuration; the agent has not been run there |
| Amazon EKS | Kubernetes 1.37, managed node groups with Amazon Linux 2023: tested. Bottlerocket, EKS Auto Mode, Fargate, Amazon Linux 2: not supported |
| Karpenter | 1.14.1 on EKS: drift (including on-demand → spot), NodeClaim deletion, spot interruption warnings – tested |
| GKE, AKS | not run yet |
| Agones | 1.61 on Cilium 1.20: tested |

| CNI | Mode under `Auto` | Status |
|---|---|---|
| Cilium (multi-pool IPAM) | keep IP | tested (lab); Phantom mode on request, tested |
| Calico (calico-ipam) | keep IP | tested (lab, VXLAN); Phantom mode tested. eBPF dataplane, IPIP and BGP modes not run |
| Flannel | Phantom | tested (lab) |
| Antrea | Phantom | tested (lab) |
| AWS VPC CNI | Phantom | tested (EKS 1.37) |
| Azure CNI, Canal, OVN-Kubernetes, Kube-OVN, kindnet | Phantom | not run on a cluster |

Per-CNI results and datapath details: [CNI.md](docs/CNI.md).

## Measured results

The **freeze** is the time the pod stands still, from the final dump to the
restored process. TCP peers notice somewhat more (their retransmission
timer backs off), UDP flows resume with the first packet. Measured in the
project's kubeadm lab (VMs, Kubernetes 1.37) and on Amazon EKS; your
numbers depend on the pod's memory, how fast it writes and the network
between the nodes.

| Scenario | Freeze |
|---|---|
| Small pods, IP kept on Cilium | 0.55–0.73 s |
| Small pods, IP kept on Calico (floor: Calico's own CNI calls) | 1.23–1.58 s |
| Small pods, new IP (Phantom mode) | 0.3–0.9 s |
| EKS 1.37, AWS VPC CNI (Phantom mode), m7i-flex.large: Minecraft Java and Bedrock, eight players each | 0.61–0.66 s (Java), 0.44–0.47 s (Bedrock); no player disconnected |
| EKS with Karpenter 1.14.1, Minecraft Bedrock with eight players: drift, deleted NodeClaim, spot interruption warning | 0.53–0.70 s, after up to 45 s waiting for the new node |
| Agones GameServer (the replacement keeps the pod's name), lab, Cilium | 1.98–2.10 s, no session reset |
| Minecraft world on an RWO block volume (Cinder), lab | 10.7–13.1 s, of which 6–9 s Kubernetes' detach and attach |

Sources: [ROADMAP.md](docs/ROADMAP.md) (where it stands),
[CNI.md](docs/CNI.md), [INSTALL.md](docs/INSTALL.md#networking-on-eks),
[AGONES.md](docs/AGONES.md), [CHANGELOG.md](CHANGELOG.md).

## Known limitations

- **Phantom mode keeps in-cluster connections only.** Peers outside the
  cluster – and, on the AWS VPC CNI, NLB/ALB *IP targets* and other EC2
  instances that reach the pod IP directly – cannot be programmed; their
  connections are closed cleanly (the application sees `ECONNABORTED` and
  can reconnect). **Use a Service with instance targets**, or a CNI that
  keeps the IP.
- **Phantom mode: new connections during the freeze.** A connection opened
  through a Service while the pod is frozen is handed back to the Service
  after the restore and completes about 3 s after the attempt, not at
  once. One opened to the *old pod IP* itself is not translated.
- **Phantom mode: the pod IP changes.** Workloads that hand their own pod
  IP to others for future connections (Kafka `advertised.listeners`, peer
  URLs, service registries) need a CNI that keeps the IP, or DNS names.
  `externalTrafficPolicy: Local` Services are not preserved.
- **Agones host ports:** players connected through a host port lose the
  connection, because the node's address changes. Use a Service per
  GameServer or a proxy.
- **Large, busy memory gives long freezes:** what pre-copy cannot catch up
  with goes into the freeze. Auto-converge slows a CPU-bound writer, not one
  paced by a timer or by I/O.
- **RWO block volumes add their detach to the freeze** (Kubernetes attaches
  to the target only after the source's detach). EBS volumes move only
  within their availability zone. Keep state that must move fast on RWX
  storage or in `emptyDir`.
- **Replacements under the same name** (StatefulSets, bare pods, Agones
  GameServers) freeze about 1–1.5 s longer: their sandbox is created inside
  the freeze.
- **Containers with stdin or a TTY are refused** by the preflight: an
  attached stream cannot move to another node. That includes the CI job pods
  of the GitLab Runner's Kubernetes executor; the runner manager itself
  migrates (measured on EKS: freeze 0.6 s, the running job's log complete).
- **A unix socket connection that is not accepted yet and already holds
  data fails the final dump** (CRIU); the migration rolls back and the pod
  continues where it was.

More detail: [CHANGELOG.md](CHANGELOG.md),
[CNI.md](docs/CNI.md), [PHANTOM-MODE.md](docs/PHANTOM-MODE.md) (section 5),
[ROADMAP.md](docs/ROADMAP.md).

## Security

Paguro moves running processes between machines, so parts of it are as
privileged as a container runtime. In short – the full model is in
[SECURITY.md](SECURITY.md):

- The **agent** runs privileged on every node (hostPID, hostNetwork, the
  host root mounted for the node installer): whoever controls an agent
  controls its node. Admission policies (Kubernetes ≥ 1.30) hold each
  agent's service account to its own node, so one node does not become the
  cluster.
- **Checkpoints are the workload's whole memory.** They travel between
  agents over mutual TLS 1.3 with a certificate per node, signed by the
  controller only for that node; on disk they are root-only and removed
  after every migration.
- The **controller** runs as non-root with no capabilities on a distroless
  image; its webhooks fail open, so a Paguro outage never blocks pod
  creation or drains.
- **Releases** – images and chart – are signed with cosign (keyless, by
  this repository's release workflow) and carry SPDX SBOM attestations;
  every release is scanned with govulncheck and grype.
- Report vulnerabilities privately through
  [GitHub security advisories](https://github.com/DPicillo/paguro/security/advisories/new),
  not in public issues.

## Documentation

| Document | For |
|---|---|
| [Helm chart](deploy/helm/paguro/README.md) | install, usage, every value, example values |
| [INSTALL.md](docs/INSTALL.md) | requirements, the Helm chart, the node installer, Amazon EKS and Karpenter, upgrades, uninstalling, troubleshooting |
| [OPERATIONS.md](docs/OPERATIONS.md) | metrics, alerts, dashboard, drains and autoscalers, long freezes, troubleshooting migrations |
| [CNI.md](docs/CNI.md) | which CNI keeps the pod IP, which uses Phantom mode, what each was tested with |
| [AGONES.md](docs/AGONES.md) | game servers managed by Agones |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, the phases of a migration, safety properties, volumes, CPUs |
| [PHANTOM-MODE.md](docs/PHANTOM-MODE.md) | how connections survive a new pod IP |
| [ROADMAP.md](docs/ROADMAP.md) | status and what comes next |
| [SECURITY.md](SECURITY.md) | security model, hardening values, verifying releases |
| [CHANGELOG.md](CHANGELOG.md) | changes, measured results, known limitations per release |

All documents: [docs/README.md](docs/README.md).

## Contributing

Bug reports, measurements from your clusters and questions are welcome in
[GitHub issues](https://github.com/DPicillo/paguro/issues). For a bug,
include the Migration's status and the controller's and both agents' logs.
Pull requests are welcome too: open an issue first for larger changes, and
sign off every commit (`git commit -s`) – contributions are accepted under
the [Developer Certificate of Origin](https://developercertificate.org).
Development setup, checks and conventions:
[CONTRIBUTING.md](CONTRIBUTING.md); how we treat each other:
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

Paguro is free software: you can redistribute it and/or modify it under the
terms of the **GNU Affero General Public License, version 3 only**
([LICENSE](LICENSE), SPDX `AGPL-3.0-only`). Commercial use is allowed; whoever
distributes Paguro – modified or not – or offers a modified version to others
over a network must make the complete source code of that version available
under the same license.

The eBPF program of Phantom mode is `GPL-2.0-only OR BSD-2-Clause`. Third-party
components, their licenses and the source code of the CRIU bundle shipped in
the node installer image: [docs/THIRD-PARTY.md](docs/THIRD-PARTY.md).

Copyright (C) 2026 David Picillo.
