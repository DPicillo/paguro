# Paguro

**Live migration of running Kubernetes pods.** Paguro moves a running pod to
another node – its memory, open files, volumes and network connections – and
resumes it there. Clients see a stall of well under a second, not a restart.

![paguro-place, a WebSocket server with a 1 GiB canvas in memory, moves to another node while the browser keeps its connection](https://raw.githubusercontent.com/DPicillo/paguro/main/docs/images/paguro-place-move.gif)

*A WebSocket server with a 1 GiB canvas in memory and a 25 GiB RWO volume
moves to the other hypervisor; the browser keeps the same TCP connection,
0 reconnects. The freeze is long here because the block volume is detached
and attached inside it – pods without RWO volumes freeze for well under a
second.*

Made for workloads that cannot simply be restarted or failed over: game
servers with players connected, long-running jobs, sessions held in memory,
single-replica services. Because Paguro answers the Eviction API,
`kubectl drain`, Karpenter and the Cluster Autoscaler move such pods instead
of killing them.

> [!NOTE]
> **Status: alpha.** The API is `paguro.dev/v1alpha1` and may change between
> minor versions. Read the
> [known limitations](https://github.com/DPicillo/paguro#known-limitations)
> before relying on it.

- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Install](#install)
- [Usage](#usage): [mark a workload](#mark-a-workload-as-migratable),
  [migrate a pod](#migrate-a-pod), [drain a node](#drain-a-node),
  [Karpenter and spot](#karpenter-cluster-autoscaler-and-spot),
  [network modes](#choose-the-network-mode),
  [volumes](#volumes-and-emptydirs), [watch a migration](#watch-a-migration)
- [Configuration](#configuration): [example values](#example-values),
  [all values](#all-values)
- [Upgrade](#upgrade), [uninstall](#uninstall),
  [troubleshooting](#troubleshooting), [documentation](#documentation)

## How it works

![How a live migration works: pre-copy while the pod runs, then a short freeze for the final dump and the restore on the target node](https://raw.githubusercontent.com/DPicillo/paguro/main/docs/images/how-it-works.png)

- **Opt in per workload** with the pod label `paguro.dev/migratable: "true"`.
  Paguro's webhook gives such pods the RuntimeClass `paguro`, a CPU baseline
  (so they can move between CPU generations) and, on Cilium, an IP of their
  own.
- **Pre-copy.** The agent on the source node checkpoints the pod with
  [CRIU](https://criu.org) in rounds while it keeps running, and streams
  memory pages, root filesystem changes and `emptyDir`s to the target node's
  agent over mutual TLS.
- **Freeze and commit.** The pod is paused, and CRIU dumps what changed
  since the last round, with the state of every TCP connection. One status
  update is the commit point: before it every failure rolls back and the
  source simply runs on.
- **Restore.** The pod's owner – Deployment, StatefulSet, Agones – gets its
  replacement on the target node, where `runc create` becomes `runc restore`;
  kubelet and containerd see an ordinary container start.
- **Network.** The pod keeps its IP where the CNI can move it (Cilium with
  multi-pool IPAM, Calico). Elsewhere it gets a new IP, and **Phantom mode**
  keeps its connections inside the cluster by eBPF translation.
- **Evictions become migrations.** `kubectl drain`, Karpenter (drift,
  consolidation, spot interruptions), the Cluster Autoscaler and managed node
  group upgrades move migratable pods – no integration with each of them.

Measured freezes: 0.3–0.9 s with a new IP (Phantom mode), 0.55–0.73 s with
the IP kept on Cilium, 1.2–1.6 s on Calico (small pods in a kubeadm lab); on
Amazon EKS 0.44–0.66 s for Minecraft servers with eight players each, none
disconnected.

## Prerequisites

| | |
|---|---|
| Kubernetes | 1.28 or later (checked on 1.28–1.37; migrations run on 1.37). The agents' admission policies need 1.30, the commit gate 1.34 – both are skipped before |
| Container runtime | containerd 2.0 or later with runc 1.2 or later; CRI-O and Docker are not supported |
| Nodes | Linux x86_64 VMs or bare metal; arm64 not yet, kind nodes cannot checkpoint |
| Kernel | 5.15 or later with `CONFIG_CHECKPOINT_RESTORE`; `CONFIG_MEM_SOFT_DIRTY` for pre-copy; time namespaces (`CONFIG_TIME_NS`) recommended |
| cgroups | v2 (unified hierarchy) |
| CRIU | 4.0 or later – the node installer ships CRIU 4.2.1 where the host has none |
| Namespace | must allow privileged pods: the agent runs privileged with hostPID and hostNetwork |
| Not supported | Fargate, EKS Auto Mode, Bottlerocket, Amazon Linux 2 and Windows nodes |

You prepare nothing on the nodes: the chart's node installer checks every
node and sets up CRIU, nftables and the containerd runtime handler `paguro`.
A node that does not qualify reports why in the agent's init container and
is left alone. Full list:
[installation guide](https://github.com/DPicillo/paguro/blob/main/docs/INSTALL.md#requirements).

## Install

```sh
helm install paguro oci://ghcr.io/dpicillo/charts/paguro --version 0.1.0 \
  -n paguro-system --create-namespace
kubectl -n paguro-system rollout status ds/paguro-agent
```

If your cluster enforces a Pod Security standard by default, create and label
the namespace first (then install without `--create-namespace`):

```sh
kubectl create namespace paguro-system
kubectl label namespace paguro-system pod-security.kubernetes.io/enforce=privileged
```

Amazon EKS, Karpenter, RKE2/k3s and image mirrors:
[installation guide](https://github.com/DPicillo/paguro/blob/main/docs/INSTALL.md).
The chart and the images are signed with cosign (keyless, by the repository's
release workflow) and carry SPDX SBOMs; verifying them:
[SECURITY.md](https://github.com/DPicillo/paguro/blob/main/SECURITY.md#supply-chain).

### Install the kubectl plugin

From the [GitHub release](https://github.com/DPicillo/paguro/releases)
(archives for Linux, macOS and Windows, with a checksum file):

```sh
VERSION=v0.1.0 OS=linux ARCH=amd64   # OS: linux, darwin, windows; ARCH: amd64, arm64
curl -fsSLO https://github.com/DPicillo/paguro/releases/download/$VERSION/kubectl-paguro_${VERSION}_${OS}_${ARCH}.tar.gz
tar -xzf kubectl-paguro_${VERSION}_${OS}_${ARCH}.tar.gz
install -m 0755 kubectl-paguro_${VERSION}_${OS}_${ARCH}/kubectl-paguro ~/.local/bin/
```

Once the plugin is listed in the krew index: `kubectl krew install paguro`.

### Verify

```sh
kubectl paguro version   # the plugin's, the controller's and every agent's release
kubectl paguro nodes     # per node: agent, release, CRIU version, CPU model and flags
```

A node shows an agent endpoint once its agent runs and holds its transfer
certificate – usually within a minute of the install.

## Usage

### Mark a workload as migratable

Put the label on the **pod template**. It takes effect when a pod is
created, so restart the workload once after adding it:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: game-server
  namespace: games
spec:
  replicas: 1
  selector:
    matchLabels: {app: game-server}
  template:
    metadata:
      labels:
        app: game-server
        paguro.dev/migratable: "true"
    spec:
      containers:
        - name: server
          image: registry.example.com/game-server:1.4
```

```sh
kubectl -n games rollout restart deployment/game-server
```

Paguro refuses, with a reason, what cannot move: containers with stdin or a
TTY, `hostPath` volumes and local PersistentVolumes, pods on nodes without an
agent.

### Migrate a pod

```sh
kubectl paguro migrate <pod> -n games --wait              # Paguro picks the target node
kubectl paguro migrate <pod> -n games --to <node> --wait  # or you do
kubectl paguro migrate <pod> -n games --freeze-budget 300ms --timeout 20m --wait
```

`--wait` follows the phases and prints the result: the freeze, what moved
and whether the IP was kept. The same as a `Migration` object – only
`podName` is required, the other fields show their defaults:

```yaml
apiVersion: paguro.dev/v1alpha1
kind: Migration
metadata:
  name: move-game-server
  namespace: games
spec:
  podName: game-server-7d9f8-x2k4p
  # targetNode: node-b      # empty: Paguro picks a compatible node
  strategy: PreCopy          # StopAndCopy: freeze at once, copy everything in the freeze
  network: Auto              # Auto | Preserve | Phantom | Generic
  cpuPolicy: Strict          # Ignore: also to nodes lacking CPU features (risk of SIGILL)
  timeoutSeconds: 600        # then rollback, if still possible
  preCopy:
    maxRounds: 8
    freezeBudgetMs: 500      # freeze once the rest fits into this
    autoConverge: true       # throttle the pod's CPU if it writes memory too fast
```

### Drain a node

```sh
kubectl drain <node> --ignore-daemonsets --delete-emptydir-data
```

Each eviction of a migratable pod becomes a migration; the drain retries
(HTTP 429, as for a PodDisruptionBudget) and goes on once the pod has moved.
Other pods are evicted as usual. `--delete-emptydir-data` only lets kubectl
evict pods with `emptyDir`s at all – for migratable pods Paguro moves their
content. At most three migrations leave a node at a time
(`controller.migrationsPerNode`); a migration that fails lets the next
eviction through, and the pod restarts as it would without Paguro.

`kubectl paguro drain <node>` migrates the migratable pods of a node
explicitly and reports each result – also with `webhook.evictions: false`.
It neither cordons the node nor evicts other pods.

### Karpenter, Cluster Autoscaler and spot

Nothing to configure on Paguro's side: Karpenter, the Cluster Autoscaler and
managed node group upgrades evict through the Eviction API, and those
evictions become migrations.

- **Karpenter** launches the replacement node while it drains the old one; a
  migration that an eviction started waits up to
  `controller.evictionTargetWait` (2 min) for it. Give the NodePool Paguro's
  startup taint, so that a new node counts as initialized only once the agent
  runs there:

  ```yaml
  apiVersion: karpenter.sh/v1
  kind: NodePool
  spec:
    template:
      spec:
        startupTaints:
          - {key: paguro.dev/agent-not-ready, effect: NoSchedule}
  ```

- **Spot interruptions** on EC2: the agent reads the instance's termination
  time (node annotation `paguro.dev/terminates-at`), and a migration starts
  only if it fits into the time left; otherwise the eviction goes through at
  once. Give Karpenter its interruption queue (`settings.interruptionQueue`)
  and more than one instance type or capacity type.

Tested with Karpenter 1.14 on EKS 1.37: drift (also on-demand → spot), a
deleted NodeClaim and spot interruption warnings, 0.53–0.70 s freezes for a
Minecraft server with eight players.

### Choose the network mode

Per migration (`spec.network`, `kubectl paguro migrate --network`) or per
workload with an annotation on the pod template:

```yaml
  template:
    metadata:
      annotations:
        paguro.dev/network: phantom   # auto | preserve | phantom | generic
```

| Mode | Pod IP | Connections | Works with |
|---|---|---|---|
| `Auto` (default) | kept where possible | – | picks `Preserve`, else `Phantom`, else `Generic` |
| `Preserve` | kept | every TCP connection and UDP flow, also to peers outside the cluster | Cilium (multi-pool IPAM), Calico (calico-ipam) |
| `Phantom` | new | inside the cluster kept by eBPF translation (TCP and UDP); peers outside the cluster are closed cleanly | any CNI: Flannel, Antrea, AWS VPC CNI, Cilium, Calico, … |
| `Generic` | new | closed right after the restore, so the application reconnects at once | any CNI |

An unknown value is refused, never read as `Auto`. Memory, open files,
`emptyDir`s and volumes move in every mode. Clients outside the cluster keep
their connections through a Service with instance targets (NodePort,
LoadBalancer); load balancers with IP targets see the new address only after
re-registration. Details:
[CNIs](https://github.com/DPicillo/paguro/blob/main/docs/CNI.md),
[Phantom mode](https://github.com/DPicillo/paguro/blob/main/docs/PHANTOM-MODE.md).

### Volumes and emptyDirs

| What | What happens |
|---|---|
| `emptyDir` | copied during pre-copy; the freeze carries only what changed. The pod's own `/dev/shm` moves too |
| RWX volumes (NFS, EFS) | written back before the final dump; file locks are handed over |
| RWO volumes (EBS, Cinder, …) | detached from the source once the pod is frozen and attached to the target – that time is part of the freeze. Multi-attach types (EBS io2, Cinder multiattach) attach during pre-copy with `agent.preAttach.enabled: true`. EBS volumes move only within their availability zone |
| `hostPath`, local PersistentVolumes | refused by the preflight: the data belongs to the node |
| Container images | pinned to the digest the source ran |

State that must move fast belongs in an `emptyDir` or on storage two nodes
can mount.

### Game servers (Agones)

With Agones installed first, the chart turns on its integration
(`agones.enabled: auto`): a GameServer moves with its game state, keeps its
name and stays `Allocated`, and Agones learns its new node. Label the pod
template of the Fleet's GameServers and migrate the pod like any other:
[Agones guide](https://github.com/DPicillo/paguro/blob/main/docs/AGONES.md).

### Watch a migration

```sh
kubectl paguro list -A                       # migrations: freeze, phase, pod, from → to, IP kept
kubectl paguro describe <migration> -n games # phases, pre-copy rounds, timing breakdown, volumes, events
kubectl get migrations -n games              # similar columns, without the plugin
kubectl get events -n games --field-selector involvedObject.kind=Migration
```

Migrations go `Pending → Preflight → PreCopy → Frozen → CuttingOver →
Restoring → Succeeded`; before the commit an error ends in `RolledBack` (the
pod runs on where it was), after it in `Failed`. A migration that an
eviction started is named `<pod>-evict-<uid>` and labelled
`paguro.dev/trigger: eviction`.

Metrics (with the Prometheus Operator, PodMonitors and alert rules are
created by default): `paguro_migrations_total{result}`,
`paguro_migration_freeze_seconds`, `paguro_migration_phase_seconds{phase}`,
`paguro_migrations_active` and more;
`monitoring.grafanaDashboard.enabled: true` adds a Grafana dashboard.
Metrics, alerts and what to do about long freezes:
[operations guide](https://github.com/DPicillo/paguro/blob/main/docs/OPERATIONS.md).

## Configuration

Every value is validated by `values.schema.json`, so a misspelled key fails
the install instead of being ignored. Set values with `-f my-values.yaml` or
`--set key=value`.

### Example values

| File | For |
|---|---|
| [`minimal.yaml`](https://github.com/DPicillo/paguro/blob/main/deploy/helm/paguro/examples/minimal.yaml) | a test cluster: one controller replica, agents only on labelled nodes, no Prometheus objects |
| [`eks-karpenter.yaml`](https://github.com/DPicillo/paguro/blob/main/deploy/helm/paguro/examples/eks-karpenter.yaml) | Amazon EKS with Amazon Linux 2023, the AWS VPC CNI and Karpenter |
| [`cilium.yaml`](https://github.com/DPicillo/paguro/blob/main/deploy/helm/paguro/examples/cilium.yaml) | Cilium with multi-pool IPAM: pods keep their IP |
| [`calico.yaml`](https://github.com/DPicillo/paguro/blob/main/deploy/helm/paguro/examples/calico.yaml) | Calico with calico-ipam: pods keep their IP |

```sh
helm install paguro oci://ghcr.io/dpicillo/charts/paguro --version 0.1.0 \
  -n paguro-system --create-namespace \
  -f https://raw.githubusercontent.com/DPicillo/paguro/main/deploy/helm/paguro/examples/eks-karpenter.yaml
```

The values most often changed: `global.imageRegistry` (a mirror),
`agent.onlyLabelledNodes`, `agent.resources` (the CPU request is the
pre-copy's speed on busy nodes), `controller.migrationsPerNode`,
`webhook.excludeNamespaces`, `cpuBaseline` (node types that change over
time) and `cni.stickyCIDR` (Cilium).

### All values

<!-- values:begin -->
<!-- Generated by hack/chartdocs from values.yaml and values.schema.json; edit those. -->

#### Images

| Key | Type | Default | Description |
|---|---|---|---|
| `global.imageRegistry` | string | `ghcr.io/dpicillo/paguro` | Registry prefix of the three images: &lt;registry&gt;/&lt;name&gt;:&lt;tag&gt;. The published chart pulls from ghcr.io/dpicillo/paguro; set a mirror (ECR, Harbor) here. |
| `global.imageTag` | string | `""` | Tag of all three images; empty: the chart's appVersion. |
| `global.imagePullPolicy` | `Always`, `IfNotPresent`, `Never` | `IfNotPresent` | Pull policy of all images. |
| `global.imagePullSecrets` | list | `[]` | Pull secrets for a private registry or mirror, as a list of {name: &lt;secret&gt;}. |
| `controller.image.name` | string | `paguro-controller` | Image name, appended to global.imageRegistry. |
| `controller.image.repository` | string | `""` | Full repository; overrides global.imageRegistry and name. |
| `controller.image.tag` | string | `""` | Image tag; empty: global.imageTag, then the chart's appVersion. |
| `agent.image.name` | string | `paguro-agent` | Image name, appended to global.imageRegistry. |
| `agent.image.repository` | string | `""` | Full repository; overrides global.imageRegistry and name. |
| `agent.image.tag` | string | `""` | Image tag; empty: global.imageTag, then the chart's appVersion. |
| `nodeInstaller.image.name` | string | `paguro-node-installer` | Image name, appended to global.imageRegistry. |
| `nodeInstaller.image.repository` | string | `""` | Full repository; overrides global.imageRegistry and name. |
| `nodeInstaller.image.tag` | string | `""` | Image tag; empty: global.imageTag, then the chart's appVersion. |

#### Controller

| Key | Type | Default | Description |
|---|---|---|---|
| `controller.replicas` | int | `2` | Controller replicas. Every replica serves the webhooks and the leader runs the migrations; two keep the webhooks reachable while one restarts (helm upgrade). 1 is fine for tests. |
| `controller.leaderElect` | bool | `true` | Leader election between the replicas; must stay true with more than one. |
| `controller.logLevel` | string | `info` | Log level: debug, info, error or a verbosity number. |
| `controller.migrationsPerNode` | int | `3` | Migrations that move pods off one node at a time; further ones wait in phase Pending while their pods run on. 0: no bound. |
| `controller.evictionTargetWait` | string | `2m` | How long a migration started by an eviction waits for a node to move to – Karpenter launches one while it drains a node (Go duration; 0: no wait). Then the eviction goes through as without Paguro. |
| `controller.extraArgs` | list | `[]` | Additional command-line arguments of the controller. |
| `controller.resources` | map | `{requests: {cpu: 100m, memory: 128Mi}, limits: {memory: 512Mi}}` | Requests and limits of the controller. |
| `controller.nodeSelector` | map | `{}` | Node selector of the controller pods. |
| `controller.tolerations` | list | `[{key: node-role.kubernetes.io/control-plane, operator: Exists, effect: NoSchedule}]` | Tolerations of the controller pods; by default they may run on control-plane nodes. |
| `controller.affinity` | map | `{}` | Affinity of the controller pods. |
| `controller.priorityClassName` | string | `""` | Priority class of the controller pods. |
| `controller.podAnnotations` | map | `{prometheus.io/scrape: "true"}` | Annotations of the controller pods; prometheus.io/port follows ports.metrics unless set here. |
| `controller.ports.webhook` | int | `9443` | Port of the admission webhooks (pods, evictions). |
| `controller.ports.metrics` | int | `8080` | Port of the Prometheus metrics. |
| `controller.ports.probes` | int | `8081` | Port of the liveness and readiness probes. |

#### Agent

| Key | Type | Default | Description |
|---|---|---|---|
| `agent.onlyLabelledNodes` | bool | `false` | Run the agent and the node installer only on nodes labelled paguro.dev/enabled=true; pods migrate only between such nodes. |
| `agent.nodeSelector` | map | `{}` | Node selector of the agent DaemonSet. |
| `agent.tolerations` | list | `[{operator: Exists}]` | Tolerations of the agent DaemonSet. The agent must run on every node a migratable pod may run on, tainted nodes included. |
| `agent.affinity` | map | `{}` | Affinity of the agent DaemonSet. |
| `agent.priorityClassName` | string | `system-node-critical` | Priority class of the agent pods. |
| `agent.ports.transfer` | int | `9555` | Port of the agent-to-agent transfer (host network). |
| `agent.ports.metrics` | int | `9556` | Port of the agent's Prometheus metrics (host network). |
| `agent.ports.health` | int | `9557` | Port of the agent's health probes (host network). |
| `agent.resources` | map | `{requests: {cpu: 200m, memory: 64Mi}, limits: {}}` | Requests and limits of the agent. The CPU request is the agent's and CRIU's weight on a busy node, and so the pre-copy's speed there. No memory limit by default: it would evict received checkpoints from the page cache and slow the restore. |
| `agent.updateStrategy` | map | `{type: RollingUpdate, rollingUpdate: {maxUnavailable: 1}}` | Update strategy of the agent DaemonSet. |
| `agent.drainTimeoutSeconds` | int | `600` | On SIGTERM (upgrade, uninstall), how long the agent lets the migrations on its node finish; its terminationGracePeriodSeconds is 15 s longer. |
| `agent.extraArgs` | list | `[]` | Additional command-line arguments of the agent. |
| `agent.stateDir` | string | `/var/lib/paguro` | Host directory where checkpoints are staged; mounted at the same path, because paguro-runc reads them outside the pod. |
| `agent.runDir` | string | `/run/paguro` | Host directory for the runtime files of the agent and paguro-runc. |
| `agent.kubeletDir` | string | `/var/lib/kubelet` | kubelet's data directory on the nodes (some distributions move it). |
| `agent.preAttach.enabled` | bool | `false` | Attach RWO volumes to the target node during pre-copy, so that the attach leaves the freeze (multi-attach volume types only, e.g. EBS io2, Cinder multiattach). Grants the agents create and delete on VolumeAttachments. |

#### Security

| Key | Type | Default | Description |
|---|---|---|---|
| `agent.testFaults` | bool | `false` | Failure tests only: honour the paguro.dev/test-fault annotation, which makes a migration fail at a named point. Never in production. |
| `agent.transferTLS.enabled` | bool | `true` | Mutual TLS for the agent-to-agent transfer, with a certificate per node that the controller signs only for that node. Disable only on an isolated network; agents with and without TLS do not migrate between each other. |
| `agent.restrictionPolicy.enabled` | bool | `true` | ValidatingAdmissionPolicy that holds every agent to its own node: its Node, its migrations, its VolumeAttachments (Kubernetes 1.30 or later; skipped before). |
| `agent.token.existingSecret` | string | `""` | Secret with the agents' shared token (key "token"); empty: generated once and kept across upgrades. |

#### Node installer

| Key | Type | Default | Description |
|---|---|---|---|
| `nodeInstaller.enabled` | bool | `true` | Prepare every node before the agent starts: CRIU, nftables, crictl, paguro-runc and the containerd runtime handler. false if the nodes are prepared otherwise (Ansible, image build). |
| `nodeInstaller.restartContainerd` | bool | `true` | Restart containerd when the runtime handler had to be added; running containers survive. false: the installer stops with a message instead. |
| `nodeInstaller.criuMinVersion` | string | `"4.0"` | Oldest host CRIU accepted; with an older one, or none, the bundled CRIU is used. |
| `nodeInstaller.requirePrecopy` | bool | `false` | Fail on nodes without soft-dirty tracking instead of warning (there, without pre-copy, all memory is copied during the freeze). |
| `nodeInstaller.containerd.binary` | string | `""` | Path of the containerd binary; empty: detected from the running process. |
| `nodeInstaller.containerd.configPath` | string | `""` | Path of containerd's config.toml; empty: from the process's --config argument. |
| `nodeInstaller.containerd.unit` | string | `""` | systemd unit of containerd; empty: detected from its cgroup. |
| `nodeInstaller.containerd.dropInDir` | string | `""` | Drop-in directory used when config.toml has no imports glob yet; empty: &lt;config dir&gt;/conf.d. |
| `nodeInstaller.resources` | map | `{requests: {cpu: 10m, memory: 32Mi}, limits: {memory: 256Mi}}` | Requests and limits of the node installer. |

#### Webhooks and RuntimeClass

| Key | Type | Default | Description |
|---|---|---|---|
| `runtimeClass.create` | bool | `true` | Create the RuntimeClass; skipped if one with this name exists that this release did not create. |
| `runtimeClass.name` | string | `paguro` | Name of the RuntimeClass that migratable pods get. |
| `runtimeClass.handler` | string | `paguro` | containerd runtime handler of the RuntimeClass, configured by the node installer. |
| `webhook.failurePolicy` | `Ignore`, `Fail` | `Ignore` | Failure policy of the pod webhook. Ignore: an unreachable controller never blocks pod creation; pods created meanwhile are reported as NotMutated. |
| `webhook.timeoutSeconds` | int | `5` | Timeout of the webhook calls in seconds. |
| `webhook.excludeNamespaces` | list | `[kube-system]` | Namespaces the webhooks never see; the release namespace is always added. |
| `webhook.extraNamespaceSelector` | list | `[]` | Additional matchExpressions for the webhooks' namespaceSelector, e.g. to opt namespaces in by label. |
| `webhook.evictions` | bool | `true` | Turn evictions of migratable pods into migrations: kubectl drain, Karpenter, the Cluster Autoscaler and node group upgrades then move such pods instead of restarting them. |

#### Network and Phantom mode

| Key | Type | Default | Description |
|---|---|---|---|
| `phantom.enabled` | bool | `true` | Load the Phantom-mode translator. Network mode Auto falls back to Phantom mode, instead of closing connections, when every node supports it. |
| `phantom.clusterCIDRs` | list | `[]` | Extra prefixes that belong to the cluster, if the CNI does not publish its pod ranges (node podCIDRs, Cilium and Calico pools and Service CIDRs are detected). |
| `phantom.steeringMark` | string | `"0x2000"` | Bit of the packet mark that routes forwarded migrated connections (pods behind a ClusterIP, NodePort clients) to the new address, as hex. The default is outside the bits of kube-proxy, Cilium, Calico and the AWS VPC CNI. |
| `cni.adapter` | `auto`, `cilium`, `calico`, `generic` | `auto` | CNI adapter: auto (detected by the controller from the CNI's CRDs), cilium, calico or generic. The chart renders the Cilium socket mount for auto and cilium. |
| `cni.stickyCIDR` | string | `10.250.0.0/16` | IPv4 range for the kept /32 addresses of migratable pods on Cilium (multi-pool IPAM); must not overlap the pod, node or VPC ranges. |
| `cni.ciliumSocketDir` | string | `/var/run/cilium` | Directory of the Cilium agent's API socket on the host. |
| `commitGate.enabled` | bool | `true` | Commit gate, a DRA driver in the agent: a replacement that keeps the IP gets its sandbox the moment the migration commits, about 0.6 s less freeze (Kubernetes 1.34 or later). |
| `commitGate.earlyHandOver` | bool | `true` | Cilium: create the replacement's sandbox while the final dump runs, about 0.15 s less freeze; a rollback gives the address back to the source. |

#### CPUs, Agones and the CRD

| Key | Type | Default | Description |
|---|---|---|---|
| `crds.install` | bool | `true` | Install and upgrade the Migration CRD with the chart (kept on uninstall). |
| `cpuBaseline` | `auto`, `off`, `x86-64-v1`, `x86-64-v2`, `x86-64-v3`, `x86-64-v4` | `auto` | CPU features migratable pods may use, so that they can move between CPU generations: auto (shared by all nodes with an agent), x86-64-v1 to x86-64-v4 (a fixed level, for node types that change) or off (no baseline). |
| `agones.enabled` | bool or `auto` | `auto` | Agones integration: GameServers move with their game state and stay Allocated. auto: when the GameServer API exists at install time (Kubernetes 1.30 or later). |

#### Monitoring

| Key | Type | Default | Description |
|---|---|---|---|
| `monitoring.prometheusRule.enabled` | bool or `auto` | `auto` | Alert rules as a PrometheusRule. auto: when the Prometheus Operator's API exists at install time. |
| `monitoring.prometheusRule.labels` | map | `{}` | Labels of the PrometheusRule, e.g. release: kube-prometheus-stack for the operator's ruleSelector. |
| `monitoring.podMonitor.enabled` | bool or `auto` | `auto` | PodMonitors for the controller and the agents. auto: when the Prometheus Operator's API exists at install time. |
| `monitoring.podMonitor.labels` | map | `{}` | Labels of the PodMonitors, for the operator's podMonitorSelector. |
| `monitoring.grafanaDashboard.enabled` | bool | `false` | The Grafana dashboard as a ConfigMap for Grafana's dashboard sidecar. |
| `monitoring.grafanaDashboard.namespace` | string | `""` | Namespace of the dashboard ConfigMap; empty: the release namespace. |
| `monitoring.grafanaDashboard.labels` | map | `{grafana_dashboard: "1"}` | Labels of the dashboard ConfigMap, for the sidecar's label selector. |

<!-- values:end -->

## Upgrade

```sh
helm upgrade paguro oci://ghcr.io/dpicillo/charts/paguro --version <version> \
  -n paguro-system --reset-then-reuse-values   # Helm 3.14 or later; or -f my-values.yaml
```

Read the version's section in the
[changelog](https://github.com/DPicillo/paguro/blob/main/CHANGELOG.md)
first: before 1.0 a minor version may change the API and the values. Not
`--reuse-values`: it carries the previous chart's defaults along, and the
schema refuses values a newer chart renamed or removed. The Migration CRD is
a chart template, so `helm upgrade` updates it too (`crds.install: false`
leaves it to you). Running migrations finish before an agent restarts, and
only agents of the same release migrate between each other.

## Uninstall

```sh
helm uninstall paguro -n paguro-system
```

The agents let the migrations on their node finish before they stop.

- The **CRD stays** (`helm.sh/resource-policy: keep`), and with it every
  Migration object. Delete it once you are done:
  `kubectl delete crd migrations.paguro.dev`.
- Secrets and ConfigMaps the controller created (`paguro-webhook-tls`,
  `paguro-agent-ca`) and, on Cilium, the sticky IP pools of running pods
  stay as well.
- The node installer's changes on the nodes stay: it records them and undoes
  exactly those in its `uninstall` mode – run it before or after
  `helm uninstall` as described in
  [Uninstalling](https://github.com/DPicillo/paguro/blob/main/docs/INSTALL.md#uninstalling).

## Troubleshooting

| Symptom | Look at |
|---|---|
| Agent pod in `Init:Error` | the node installer's report: `kubectl -n paguro-system logs <agent-pod> -c node-installer` – one line per check (kernel, cgroups, containerd, runc, CRIU) and what is missing |
| Migration rejected in `Preflight` | `kubectl paguro describe <migration>`: the message names the reason (CPU features, volumes, host ports, stdin, a missing agent, …) |
| Migration `RolledBack` | the abort reason in the message and the source agent's log; the pod ran on where it was |
| Pod not migratable although labelled | it was created while the webhook was unreachable: `kubectl get events -A --field-selector reason=NotMutated`, then restart it |
| Two nodes never migrate to each other, or a node is never a target | `kubectl paguro version` (agents of different releases are not paired) and `kubectl paguro nodes` (no agent endpoint: the transfer certificate is missing, see `kubectl get csr`) |

More – long freezes, a restore that cold-starts, Agones:
[operations guide](https://github.com/DPicillo/paguro/blob/main/docs/OPERATIONS.md#troubleshooting),
[installation guide](https://github.com/DPicillo/paguro/blob/main/docs/INSTALL.md#troubleshooting).
For a bug report, include the Migration's status and the logs of the
controller and both agents.

## Documentation

- [The story behind Paguro](https://www.picillo.de/blog/kubernetes-pod-live-migration/)
- [Installation](https://github.com/DPicillo/paguro/blob/main/docs/INSTALL.md) –
  requirements, Amazon EKS, Karpenter, the node installer, uninstalling
- [Operations](https://github.com/DPicillo/paguro/blob/main/docs/OPERATIONS.md) –
  metrics, alerts, drains, long freezes, troubleshooting
- [Networks and CNIs](https://github.com/DPicillo/paguro/blob/main/docs/CNI.md)
  and [Phantom mode](https://github.com/DPicillo/paguro/blob/main/docs/PHANTOM-MODE.md)
- [Agones game servers](https://github.com/DPicillo/paguro/blob/main/docs/AGONES.md)
- [Architecture](https://github.com/DPicillo/paguro/blob/main/docs/ARCHITECTURE.md)
  and [security model](https://github.com/DPicillo/paguro/blob/main/SECURITY.md)
- [Changelog](https://github.com/DPicillo/paguro/blob/main/CHANGELOG.md) and
  [issues](https://github.com/DPicillo/paguro/issues)

## License

GNU Affero General Public License, version 3 only (`AGPL-3.0-only`). The
eBPF program of Phantom mode is `GPL-2.0-only OR BSD-2-Clause`; the CRIU
build in the node installer image is GPL-2.0 with its source in the image
`paguro-node-installer-sources`.
