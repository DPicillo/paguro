# Installing Paguro

Paguro is installed with a single Helm chart, published as
`oci://ghcr.io/dpicillo/charts/paguro` (source: `deploy/helm/paguro`). The
chart contains the controller, the `paguro-agent` DaemonSet and a **node
installer**. The installer runs as an initContainer of every agent pod and
prepares the node: CRIU, nftables, `/etc/criu/runc.conf`, the `paguro-runc`
wrapper and the containerd runtime handler `paguro`. You don't need Ansible
or an image build on the nodes.

```
helm install paguro oci://ghcr.io/dpicillo/charts/paguro --version 0.1.0 \
  -n paguro-system --create-namespace
```

The published chart pulls the release images from `ghcr.io/dpicillo/paguro`
(signed, with SBOMs: [SECURITY.md](../SECURITY.md#supply-chain)). The chart
in the source tree points at a local development registry
(`localhost:5000/paguro`): install it from a checkout with `--set
global.imageRegistry=<registry> --set global.imageTag=<tag>` and images
you built yourself ([below](#building-and-publishing-the-images)).

## Contents

1. [Requirements](#requirements)
2. [Building and publishing the images](#building-and-publishing-the-images)
3. [On-premises installation (kubeadm, RKE2, k3s)](#on-premises-installation)
4. [Amazon EKS](#amazon-eks)
5. [What the node installer does](#what-the-node-installer-does)
6. [Marking workloads as migratable](#marking-workloads-as-migratable)
7. [Uninstalling](#uninstalling)
8. [Troubleshooting](#troubleshooting)

---

## Requirements

| Component | Requirement | Checked by | Notes |
|---|---|---|---|
| Kernel | >= 5.15 | installer (hard) | Ubuntu 22.04+, Debian 12, AL2023 (6.1/6.12), RHEL 9 |
| `CONFIG_CHECKPOINT_RESTORE=y` | required | installer + `criu check` (hard) | basis for CRIU |
| `CONFIG_MEM_SOFT_DIRTY=y` | strongly recommended | installer (warning) | pre-copy rounds; without it the whole RAM is copied during the freeze. `nodeInstaller.requirePrecopy=true` makes it a hard failure |
| Time namespaces (`CONFIG_TIME_NS`, kernel 5.6+) | recommended | installer (warning) | paguro-runc gives each container its own time namespace so that `CLOCK_MONOTONIC` keeps running smoothly after a restore |
| `CONFIG_USERFAULTFD` | optional | info only | lazy restore (not used by default) |
| nftables in the kernel (`nf_tables`) | recommended | `criu check --feature network_lock_nftables` | otherwise `network-lock iptables` |
| cgroup v2 (unified) | required | installer (hard) | |
| containerd | >= 2.0 | installer (hard) | tested: 2.0.7, 2.1.5, 2.4.1. CRI-O and Docker are not supported |
| runc | >= 1.2 | installer (hard) | |
| CRIU | >= 4.0 with nftables | installer | ships with the installer (4.2.1) if the host has nothing usable |
| `nsenter`, `ip` on the host | required | installer (hard) | util-linux, iproute2 (present on every common distribution) |
| Architecture | x86_64 | installer | **arm64: not yet.** The images are built for amd64 only, and CRIU has no pre-copy on arm64 (no soft-dirty tracking), so the freeze would last for the whole memory dump |
| Kubernetes | >= 1.28 | Helm | installed and checked on 1.28–1.37 (kind), migrations run on 1.37; the admission policies for the agents need 1.30 (skipped before), the commit gate 1.34 |
| Pod Security | namespace `privileged` | – | the agent runs privileged with hostPID/hostNetwork |
| Certificate signing | custom signers allowed | – | each agent's transfer certificate comes from a CertificateSigningRequest for the signer `paguro.dev/agent`, signed by the controller (works on EKS, GKE, AKS) |

Security model, what a compromised node can and cannot do, and the
hardening values: [SECURITY.md](../SECURITY.md). After a fresh install the
agents accept migrations once their certificate is signed – usually within a
minute (kubelet's next sync brings the CA bundle).

Different CPUs: migratable pods get a CPU baseline when they are created
(`cpuBaseline`, default `auto` – the features all nodes share) and start
with glibc, Go, OpenSSL, the JVM, .NET and PyTorch limited to it, so they can
move between CPU generations and vendors' instance types. With node types
that change over time (autoscaling across instance families), set a fixed
level such as `cpuBaseline: x86-64-v3`. Code that detects CPU features on its
own (Node.js/V8, Rust, numpy) is not covered; see
[ARCHITECTURE.md](ARCHITECTURE.md), "Different CPUs".

## Building and publishing the images

Only needed for a registry of your own or a modified Paguro – the release
images are on `ghcr.io/dpicillo/paguro`. The chart expects three images
under one registry prefix and tag:
`<registry>/paguro-controller:<tag>`, `<registry>/paguro-agent:<tag>`,
`<registry>/paguro-node-installer:<tag>`.

```
make controller-push installer-push PAGURO_REGISTRY=registry.example.com/paguro TAG=v0.1.0
make agent-image PAGURO_REGISTRY=registry.example.com/paguro TAG=v0.1.0 && docker push registry.example.com/paguro/paguro-agent:v0.1.0
# or all in one go:
make images-push PAGURO_REGISTRY=registry.example.com/paguro TAG=v0.1.0

# A registry without TLS (development clusters), via crane; PUSH_REGISTRY
# is the address this machine reaches it under:
make images-crane-push PUSH_REGISTRY=registry.example.com:5000 TAG=v0.1.0
```

`make installer-test` runs the node installer against fake host roots
(containerd 2.0/2.1/2.4, kubeadm, EKS AL2023, a config with and without
imports, no config at all) and checks idempotency, TOML validity and a clean
uninstall. No cluster is needed.

## On-premises installation

```
kubectl create namespace paguro-system
kubectl label namespace paguro-system pod-security.kubernetes.io/enforce=privileged
helm install paguro oci://ghcr.io/dpicillo/charts/paguro --version 0.1.0 -n paguro-system
kubectl -n paguro-system rollout status ds/paguro-agent
```

(`--create-namespace` works as well when the cluster does not enforce a Pod
Security standard by default.)

Common values (every value with its default and meaning:
[the chart's README](../deploy/helm/paguro/README.md#all-values); validated
by `values.schema.json`):

| Value | Default | Meaning |
|---|---|---|
| `agent.onlyLabelledNodes` | `false` | only nodes with `paguro.dev/enabled=true` (agent, installer, and `scheduling` of the RuntimeClass) |
| `agent.nodeSelector` / `agent.tolerations` | `{}` / `Exists` | agent placement |
| `nodeInstaller.enabled` | `true` | `false` if the nodes are already prepared (Ansible, golden image); then only paguro-runc is copied |
| `nodeInstaller.restartContainerd` | `true` | `false`: the installer does not restart containerd but fails with instructions |
| `nodeInstaller.containerd.*` | auto | binary, config, systemd unit, drop-in directory (detected from the running process) |
| `runtimeClass.create` | `true` | skipped automatically if a foreign RuntimeClass `paguro` already exists |
| `webhook.excludeNamespaces` | `[kube-system]` | the release namespace is always added |
| `cni.adapter` | `auto` | hint: `cilium`, `calico`, `generic` (see below) |
| `cni.stickyCIDR` | `10.250.0.0/16` | range for sticky /32 IPs (Cilium); must not overlap the pod CIDRs |
| `cpuBaseline` | `auto` | CPU features migratable pods may use (`auto`: shared by all nodes; `x86-64-v2/v3/v4`; `off`), so they can move between different CPUs |
| `phantom.enabled` | `true` | Phantom mode ([PHANTOM-MODE.md](PHANTOM-MODE.md)): new IP, in-cluster connections kept; `Auto` uses it when the IP cannot be kept and every node supports it |
| `phantom.clusterCIDRs` | `[]` | extra prefixes that belong to the cluster, if the CNI does not publish its pod ranges (node podCIDRs, Cilium/Calico pools and Service CIDRs are detected) |
| `phantom.steeringMark` | `"0x2000"` | the bit of the packet mark that routes forwarded migrated connections (pods behind a ClusterIP, NodePort clients) to the new address; set only on their packets and only until the routing decision. Outside the bits of kube-proxy (`0x4000`, `0x8000`), Cilium (`0x0F00`, `0x1E00`, identities), Calico (`0xffff0000`) and the AWS VPC CNI (`0x80`); change it only if something else on the nodes uses it |
| `crds.install` | `true` | install and upgrade the Migration CRD with the chart; `false` if CRDs are managed separately |

### Upgrading

```
helm upgrade paguro oci://ghcr.io/dpicillo/charts/paguro --version <version> \
  -n paguro-system -f my-values.yaml
```

Read the version's section in [CHANGELOG.md](../CHANGELOG.md) first:
before 1.0 a minor version may change the API and the chart's values. Keep
the values you set in a file and pass it to every upgrade, or use
`--reset-then-reuse-values` (Helm ≥ 3.14): it re-applies the values you set
and takes every default from the new chart. Not `--reuse-values`: it also
carries the *previous chart's defaults* along – a default the new chart
changed does not arrive, and the chart's schema refuses every value it no
longer knows, so the first release that renames or removes one fails the
upgrade.

The Migration CRD is a template of the chart (not in `crds/`, which Helm
never upgrades), so `helm upgrade` brings new status fields along – an old
CRD would make the API server drop them silently. With `crds.install:
false`, apply the release's CRD yourself before the upgrade:
`kubectl apply --server-side -f
https://raw.githubusercontent.com/DPicillo/paguro/<tag>/deploy/crds/paguro.dev_migrations.yaml`.

Agents and the controller restart during an upgrade. Running migrations
finish first: an agent that gets SIGTERM marks its node as draining
(annotation `paguro.dev/agent-draining`, shown by `kubectl paguro nodes`),
is chosen for no new migration and exits once the migrations it takes part
in have ended – at most `agent.drainTimeoutSeconds` (600 s). Migrations run
only between agents of the same release (`paguro.dev/agent-version`): while
the agents roll out, a node with the new release and one with the old are
not paired. Measured: `helm upgrade` 15 s into the pre-copy of a
Minecraft server (8 players, 2.5 GiB) – the source's agent waited 76 s
until the migration had succeeded, the controller changed its leader in
between, no player was disconnected; before the drain the same upgrade
rolled the migration back. With two controller replicas
(the default) the pod webhook stays reachable throughout: every replica
serves it, the interception state lives in the Migration objects, and a
replica keeps serving for 5 s after its endpoint was removed (measured:
three controller rollouts, 116 pods created meanwhile, none unmutated).
Phantom-mode translations of finished migrations stay in place across agent
restarts (pinned eBPF maps and links). Pods created while the controller's
webhook is unreachable are reported (see below).

### kubeadm / plain containerd

Works out of the box. If `/etc/containerd/config.toml` has no `imports` glob,
the installer adds `imports = ["/etc/containerd/conf.d/*.toml"]` (backup:
`config.toml.pre-paguro`, marker comment `# paguro-node-installer:`) and writes
the handler to `/etc/containerd/conf.d/paguro.toml`. containerd is restarted
once. If you manage `config.toml` with configuration management (Ansible,
Puppet), add the imports line there as well, or define the handler there
directly. The installer recognises an existing, correct handler and leaves it
alone.

### RKE2 / k3s

The containerd config is regenerated from a template on every start. Newer
releases import `…/agent/etc/containerd/config-v3.toml.d/*.toml` (k3s:
`/var/lib/rancher/k3s/agent/etc/containerd/`, RKE2:
`/var/lib/rancher/rke2/agent/etc/containerd/`). The installer finds this
import and places its drop-in there. The restart affects the unit that owns
containerd (`k3s.service`, `rke2-agent.service`), which also restarts the
kubelet; running containers survive. Releases without that import: create a
`config-v3.toml.tmpl` with the handler (see the drop-in content below) or
update. Limitation: the agent calls `runc` through the PATH; k3s/RKE2 ship runc
under `/var/lib/rancher/…/bin`. The installer writes the path to
`/etc/paguro/runc-path` for paguro-runc, but the agent itself has not been
tested on k3s/RKE2.

## Amazon EKS

| Node type | Status | Why |
|---|---|---|
| **Managed node groups / self-managed, AL2023 AMI** | supported | the node installer does everything |
| Bottlerocket | not supported out of the box | see below |
| EKS Auto Mode | not supported | its nodes are Bottlerocket, managed by AWS (see below) |
| Fargate | **not supported** | no privileged pods, no hostPID/hostNetwork, no DaemonSets, no access to containerd |
| AL2 AMI | not supported | containerd 1.7, cgroup v1 (end of life) |
| Windows | not supported | no CRIU |

### AL2023 (managed node groups)

```
helm install paguro oci://ghcr.io/dpicillo/charts/paguro --version 0.1.0 \
  -n paguro-system --create-namespace
# images mirrored to ECR instead of ghcr.io:
#   --set global.imageRegistry=<account>.dkr.ecr.<region>.amazonaws.com/paguro
```

What happens on an AL2023 node:

* `nodeadm` renders `/etc/containerd/config.toml` (schema version 3 for
  containerd 2.x) **without an `imports` line**, with `runc` at
  `/usr/sbin/runc`, `SystemdCgroup = true` and
  `base_runtime_spec = /etc/containerd/base-runtime-spec.json`. The installer
  adds the imports line, writes `/etc/containerd/conf.d/paguro.toml` in the
  same schema version, copies `SystemdCgroup` **and `base_runtime_spec`** from
  the default handler (so restored pods get the same rlimits as all others)
  and restarts containerd once.
* CRIU and crictl are not part of the AMI. The installer provides them under
  `/opt/paguro` (self-contained, with its own glibc, verified on AL2023 with
  glibc 2.34: `criu check` → "Looks good", `network_lock_nftables` and
  `mem_dirty_track` supported).
* **nodeadm rewrites `config.toml` when the node boots.** The imports line is
  then gone; the installer adds it again on the next agent start, which costs
  one containerd restart per boot. To avoid that, put the handler directly into
  the launch template's NodeConfig. nodeadm merges it into `config.toml`, and
  the installer then reports "already configured" and restarts nothing:

  ```yaml
  # user data (MIME part application/node.eks.aws)
  apiVersion: node.eks.aws/v1alpha1
  kind: NodeConfig
  spec:
    containerd:
      config: |
        [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.paguro]
        runtime_type = 'io.containerd.runc.v2'
        pod_annotations = ['paguro.dev/*']
        container_annotations = ['paguro.dev/*']
        base_runtime_spec = '/etc/containerd/base-runtime-spec.json'
        [plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.paguro.options]
        BinaryName = '/usr/local/bin/paguro-runc'
        SystemdCgroup = true
  ```

  Important: use v3 table names (`io.containerd.cri.v1.runtime`) here. With
  v2 names (`io.containerd.grpc.v1.cri`), nodeadm falls back to the v2
  template and migrates it.

### Bottlerocket

Not supported by the DaemonSet installer, for structural reasons:

* The root filesystem is **read-only** (dm-verity). `/usr/local/bin`,
  `/usr/local/sbin` and `/opt` cannot be written; paguro-runc and CRIU have
  nowhere to go.
* `/etc/containerd/config.toml` is **generated from the settings API**
  (templates in the OS image) on every boot and every settings change. There is
  no imports directory and no setting for additional runtime handlers.
* There is no shell or systemd access from the host; changes are only possible
  through API settings and **bootstrap containers** (which run before
  containerd/kubelet start).

A port would need a bootstrap container that places CRIU, paguro-runc and the
handler in writable locations before containerd starts, and that requires
either a custom Bottlerocket variant or upstream support for additional runtime
handlers. Use AL2023 for Paguro node groups.

**EKS Auto Mode** runs Bottlerocket on nodes that AWS manages: no
bootstrap containers and no settings of one's own. Tried on 2026-10-07
(Bottlerocket 2026.9.24, kernel 6.18, containerd 2.2.8): the kernel has
everything CRIU needs, and the node installer stops with "host has no
'nsenter' in PATH", "host has no 'ip' in PATH" and "runc not found on the
host". Give a cluster with Auto Mode a managed node group with AL2023 for
the workloads that should migrate.

### Networking on EKS

| CNI | Paguro mode | IP preserved | Connections preserved |
|---|---|---|---|
| **AWS VPC CNI** (default) | Phantom | no (new IP) | **yes** within the cluster (TCP and UDP); peers outside the cluster are closed cleanly |
| **Cilium** in **overlay/tunnel mode** (VXLAN/Geneve) with **multi-pool IPAM** | keep IP | yes | yes, also to peers outside the cluster |
| Calico (overlay, Calico IPAM) | keep IP | yes | yes |
| Cilium in ENI mode | Phantom | no | within the cluster |

With the VPC CNI, every pod IP is a secondary IP of an ENI of *that*
instance; an IP cannot move to another instance without ENI operations,
which is too slow and too invasive. Paguro picks Phantom mode instead
([PHANTOM-MODE.md](PHANTOM-MODE.md)): the restored pod gets a new IP, and its
connections within the cluster keep the old one. The pods' IPs come from
the nodes' VPC subnets, so each agent publishes its node's subnets
(annotation `paguro.dev/node-subnets`) and Phantom mode counts them as
in-cluster. Tested on EKS 1.37 with AL2023 nodes (2026-10-07): Minecraft
Java (TCP) 610/655 ms freeze, Minecraft Bedrock (UDP) 443/466 ms, eight
players each, 0 disconnects. RAM state, open files, PVCs and root
filesystem changes are preserved in every mode. To keep the IP itself
(peers outside the cluster, NLB/ALB IP targets), use Cilium in tunnel
mode with multi-pool IPAM and a sticky range (`cni.stickyCIDR`) that
overlaps neither the VPC nor the pod CIDRs.

### Karpenter

Nothing to configure on Paguro's side: Karpenter evicts through the
Eviction API, and Paguro's eviction webhook turns each eviction of a
migratable pod into a migration ([OPERATIONS.md](OPERATIONS.md), "Move
everything off a node"). Tested with Karpenter 1.14.1 on EKS 1.37: drift
(including a move from on-demand to spot), a deleted NodeClaim and spot
interruption warnings. For spot, give Karpenter its interruption queue
(`settings.interruptionQueue`), and give the NodePool more than one
instance type or capacity type: after an interruption Karpenter avoids
that spot offering for a few minutes, and with nothing else allowed the
replacement – and with it the migration's target – waits.

Give the NodePool Paguro's startup taint. Karpenter then counts a new node
as initialized only once Paguro's agent runs on it and has removed the
taint, and drains a drifted or expiring node only toward a node that can
take its pods' migrations:

```yaml
spec:
  template:
    spec:
      startupTaints:
        - {key: paguro.dev/agent-not-ready, effect: NoSchedule}
```

Nodes that Paguro's agents do not run on (`agent.onlyLabelledNodes`) must
not get the taint – nothing would remove it.

### Storage on EKS (EBS)

* EBS volumes are **RWO and bound to one AZ**: like Cinder, the volume is
  detached from the source node after the freeze and attached to the target
  node. Pods with EBS PVCs can **only be migrated within the same AZ**.
  Paguro's placement respects the PV's node affinity.
* **io2 Multi-Attach** (`multiAttachEnabled: true` in the StorageClass of the
  EBS CSI driver, Nitro instances in the same AZ): the target agent attaches
  the volume during pre-copy (pre-attach). Attaching then disappears from the
  freeze; the volume is still only mounted after the source has unmounted it.
  gp3/io1 cannot do this, so the attach time stays in the freeze.
* EFS (RWX) needs no detach.

## What the node installer does

Image `paguro-node-installer` (Alpine + `/opt/paguro` bundle), script
`build/node-installer/install.sh`. It runs privileged with hostPID and the host
root at `/host`, and runs host programs via `nsenter -t 1` in the host's
namespaces. It **never writes to the Kubernetes API**. Every run is idempotent,
and on a prepared node it changes nothing and finishes in under a second.

| Step | Behaviour | Respects existing installs |
|---|---|---|
| Preflight | architecture, kernel, kernel config, cgroup v2, containerd >= 2.0, runc >= 1.2, `nsenter`/`ip` | hard failures stop the run **before** any change |
| Bundle | `/opt/paguro/{bin,lib}`: CRIU 4.2.1 (nftables), nft 1.0.9, crictl 1.37 | only installed if the host lacks one of the tools |
| criu | symlink `/usr/local/sbin/criu → /opt/paguro/bin/criu` | **only** if the host has no criu >= 4.0 in containerd's PATH. Never a downgrade; an outdated binary at exactly that location is moved to `criu.pre-paguro` |
| nft, crictl | symlink to `/usr/local/sbin` | only if missing |
| `/etc/criu/runc.conf` | `ghost-limit 1G`, `network-lock nftables` (iptables fallback) | only if absent or carrying our marker line; a foreign file is kept (and reported) |
| paguro-runc | `/usr/local/bin/paguro-runc`, copy + rename (atomic) | comes from the agent image (initContainer `stage-runtime`), so it always matches the agent version |
| containerd handler | drop-in in the directory the main config imports, otherwise `<config dir>/conf.d` + imports line | an existing correct handler is left alone; a foreign, *incorrect* handler is a hard failure |
| Validation | `containerd config dump` with the new config **before** the restart: the handler must be visible, and **every other setting must be byte-for-byte identical**, otherwise roll back | |
| Restart | `systemctl restart <unit>`, only if the running daemon does not serve the handler yet (`crictl info`) | containers survive (`KillMode=process`), the kubelet reconnects |
| `criu check` | plus `--feature mem_dirty_track`, `--feature network_lock_nftables` | |

**Why the drop-in uses the main config's schema version:** containerd 2.0/2.1
migrates every imported file to the main config's version separately and then
merges them. A v3 drop-in (`io.containerd.cri.v1.runtime`) next to a v2 main
config (`io.containerd.grpc.v1.cri`) silently **wipes** the runc options and
the sandbox image of the main config. A v2 drop-in next to a v3 main config is
ignored. The installer therefore writes `version = N` and the matching table
names of the main config (tested with 2.0.7, 2.1.5, 2.4.1).

Drop-in on a kubeadm node (schema 3):

```toml
# Managed by paguro-node-installer – changes are overwritten.
version = 3

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.paguro]
  runtime_type = 'io.containerd.runc.v2'
  pod_annotations = ['paguro.dev/*']
  container_annotations = ['paguro.dev/*']

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.paguro.options]
  BinaryName = '/usr/local/bin/paguro-runc'
  SystemdCgroup = true
```

**Why the CRIU bundle has its own glibc:** CRIU built on Ubuntu 24.04 needs
glibc 2.38+ symbols, but AL2023 only has 2.34. Static linking fails on
libnftables, which has no static library. The bundle therefore ships all
libraries *including* glibc and the dynamic loader under `/opt/paguro/lib`;
the binaries are patched with patchelf (`PT_INTERP=/opt/paguro/lib/ld-linux-x86-64.so.2`,
`DT_RPATH=/opt/paguro/lib`). That avoids `LD_LIBRARY_PATH`, which would leak
into the programs CRIU and runc start. Verified on Ubuntu 22.04/24.04,
Debian 12 and Amazon Linux 2023.

PATH requirement: paguro-runc runs with containerd's environment and calls
`nsenter`, `nft`, `ip` and (via runc) `criu` **by name**; the agent calls
`criu`, `runc` and `crictl` via `nsenter` with the standard PATH. The installer
therefore only links into `/usr/local/sbin` (part of the systemd default PATH)
and checks that all tools are reachable through containerd's PATH (read from
`/proc/<pid>/environ`).

Manual run on a single node (for example before a rollout). `check` only
reports and never changes anything; with `install` it does the same as the
initContainer:

```yaml
apiVersion: v1
kind: Pod
metadata: {name: paguro-node-check, namespace: paguro-system}
spec:
  nodeName: <node>
  restartPolicy: Never
  hostPID: true
  hostNetwork: true
  tolerations: [{operator: Exists}]
  containers:
    - name: installer
      image: <registry>/paguro-node-installer:<tag>
      args: ["check"]
      securityContext: {privileged: true}
      volumeMounts: [{name: host, mountPath: /host, mountPropagation: HostToContainer}]
  volumes: [{name: host, hostPath: {path: /, type: Directory}}]
```

```
kubectl apply -f node-check.yaml; kubectl -n paguro-system logs -f paguro-node-check
kubectl -n paguro-system delete pod paguro-node-check
```


## Marking workloads as migratable

```yaml
spec:
  template:
    metadata:
      labels:
        paguro.dev/migratable: "true"   # must be set at pod creation
```

```
kubectl paguro migrate <pod> -n <ns> --to <node> --wait
kubectl paguro drain <node>
kubectl paguro list
```

Install the plugin from the GitHub release (archives for Linux, macOS and
Windows, with a checksum file), or build it from source with
`make kubectl-plugin`:

```
VERSION=v0.1.0 OS=linux ARCH=amd64
curl -fsSLO https://github.com/DPicillo/paguro/releases/download/$VERSION/kubectl-paguro_${VERSION}_${OS}_${ARCH}.tar.gz
tar -xzf kubectl-paguro_${VERSION}_${OS}_${ARCH}.tar.gz
install -m 0755 kubectl-paguro_${VERSION}_${OS}_${ARCH}/kubectl-paguro ~/.local/bin/
kubectl paguro version   # the plugin's, the controller's and the agents' versions
```

Once the plugin is in the krew index: `kubectl krew install paguro`.

How a migration treats the pod's IP is chosen per migration
(`kubectl paguro migrate --network Auto|Preserve|Phantom|Generic`) or per
workload with an annotation in the pod template:

```yaml
      annotations:
        paguro.dev/network: phantom   # preserve | phantom | generic; default: Auto
```

`Auto` keeps the IP when the CNI can (Calico with calico-ipam, Cilium with
Paguro's sticky IPs), otherwise it uses Phantom mode when every node
supports it ([PHANTOM-MODE.md](PHANTOM-MODE.md)). Under Cilium, pods
annotated `phantom` or `generic` get no sticky IP – they never need one.
Any other value is refused, not read as `Auto`: the webhook does not
create the pod (the message names the annotation), and preflight fails a
migration of a pod that already carries it. A typo in a Deployment's
template therefore stops its pods from being created – the ReplicaSet
reports `FailedCreate` with that message – until the value is fixed.

The label takes effect when the pod is **created**: Paguro's webhook gives
the pod the RuntimeClass `paguro` (own time namespace, so monotonic clocks
continue after a move; Multipath TCP disabled in its network namespace,
see below) and, under Cilium, a sticky IP. Labeling a running pod does
nothing until it is restarted.

The webhook fails open: if it is unreachable – while the controller
restarts during `helm upgrade`, for instance – pods are created anyway,
unmutated. Paguro reports each such pod with a `NotMutated` warning event
and counts them in the metric `paguro_unmutated_pods`. Restart them
(`kubectl rollout restart`) to make them fully migratable:

```
kubectl get events -A --field-selector reason=NotMutated
```

**Multipath TCP.** CRIU cannot checkpoint MPTCP sockets, and Go ≥ 1.24
opens listeners as MPTCP by default when the kernel allows it
(`sysctl net.mptcp.enabled` = 1, the default on Ubuntu 24.04, for
example). Paguro sets
`net.mptcp.enabled=0` in the network namespace of every pod under its
RuntimeClass; applications, Go included, then fall back to plain TCP.
A pod started without the RuntimeClass that holds MPTCP sockets is
rejected before it is frozen, with a message saying what to do (restart
it with the label, or set `GODEBUG=multipathtcp=0`).

## Uninstalling

```
helm uninstall paguro -n paguro-system
```

Removed: controller, agent DaemonSet, webhook, RBAC, the RuntimeClass (if it
was created by the chart) and the agent token (if it was created by the chart).

**Left behind** (on purpose):

| What | Why | Cleanup |
|---|---|---|
| CRD `migrations.paguro.dev` + all migrations | `helm.sh/resource-policy: keep` – deleting the CRD deletes every Migration | `kubectl delete crd migrations.paguro.dev` |
| Secrets `paguro-webhook-tls`, `paguro-agent-ca`, ConfigMap `paguro-agent-ca` | created by the controller | `kubectl -n paguro-system delete secret paguro-webhook-tls paguro-agent-ca; kubectl -n paguro-system delete configmap paguro-agent-ca` |
| CertificateSigningRequests `paguro-agent-*` | the agents' requests | removed by Kubernetes an hour after they were signed |
| `CiliumPodIPPool`s with label `app.kubernetes.io/managed-by=paguro` | sticky IPs of running pods; deleting them breaks their IP | `kubectl delete ciliumpodippools -l app.kubernetes.io/managed-by=paguro` (only once no migratable pods are left) |
| Node annotations `paguro.dev/*` | agent | `kubectl annotate node --all paguro.dev/cpu-flags- paguro.dev/cpu-model- paguro.dev/agent-endpoint- paguro.dev/criu-version-` |
| **On the nodes**: drop-in, imports line, symlinks, `/opt/paguro`, `runc.conf`, `paguro-runc`, `/var/lib/paguro`, `/run/paguro` | the DaemonSet is gone, so nothing runs that could clean up | see below |

The node installer records everything it has changed in
`/etc/paguro/node-installer.state` and undoes exactly that with `uninstall`
(restoring the imports line byte for byte, removing only its own symlinks and
files with its marker, then restarting containerd). **Before** `helm uninstall`,
or afterwards with a one-off DaemonSet:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: paguro-node-cleanup, namespace: paguro-system}
spec:
  selector: {matchLabels: {app: paguro-node-cleanup}}
  template:
    metadata: {labels: {app: paguro-node-cleanup}}
    spec:
      hostPID: true
      hostNetwork: true
      tolerations: [{operator: Exists}]
      initContainers:
        - name: uninstall
          image: <registry>/paguro-node-installer:<tag>
          args: ["uninstall"]
          securityContext: {privileged: true}
          volumeMounts: [{name: host, mountPath: /host}]
      containers:
        - {name: done, image: <registry>/paguro-node-installer:<tag>, command: ["sleep", "infinity"]}
      volumes: [{name: host, hostPath: {path: /}}]
```

```
kubectl apply -f node-cleanup.yaml && kubectl -n paguro-system rollout status ds/paguro-node-cleanup
kubectl -n paguro-system delete ds paguro-node-cleanup
# afterwards on each node, if needed: rm -rf /var/lib/paguro /run/paguro /etc/paguro /var/log/paguro
```

Not covered by `uninstall`: a handler that was **not** installed by the
installer (Ansible, NodeConfig) and `config.toml.pre-paguro` (kept as a
backup). Pods that still use `runtimeClassName: paguro` keep running; new ones
no longer start once the handler is removed.

## Troubleshooting

**Agent pod in `Init:Error` / `Init:CrashLoopBackOff`**

```
kubectl -n paguro-system logs <paguro-agent-xyz> -c node-installer
```

At the end of the log there is a report with one line per step
(`ok`/`installed`/`warn`/`missing`) and the errors, for example:

```
containerd             ok         2.4.1 (/usr/local/bin/containerd, config /etc/containerd/config.toml, unit containerd.service)
runc                   ok         1.5.2 (/usr/local/sbin/runc)
containerd-handler     ok         'paguro' already configured outside the installer – left alone
criu-check             ok         Looks good.
result: node already prepared, nothing changed
```

| Message | Cause / fix |
|---|---|
| `containerd X is too old` | containerd 1.x: update the node image (EKS: AL2023 instead of AL2) |
| `kernel lacks CONFIG_CHECKPOINT_RESTORE` / `criu check failed` | kernel without C/R support; a different kernel/AMI is needed |
| `cgroup v2 required` | boot with `systemd.unified_cgroup_hierarchy=1` |
| `containerd already has a runtime 'paguro' that is not ours` | foreign handler with a different BinaryName/annotations; fix or remove it |
| `adding the drop-in changed other containerd settings – rolled back` | the main config has an unusual structure; the diff is printed above the message. Add the handler by hand |
| `containerd must be restarted` | `nodeInstaller.restartContainerd=false`: run `systemctl restart containerd` on the node |
| `'nft' is not reachable via containerd's PATH` | containerd unit with its own `Environment=PATH` without `/usr/local/sbin` |

**On the node**

```
containerd config dump | grep -A12 'runtimes.paguro]'    # effective configuration
crictl info | grep -A8 '"paguro"'                        # what the running containerd actually serves
criu --version; criu check; criu check --feature mem_dirty_track; criu check --feature network_lock_nftables
cat /etc/criu/runc.conf
cat /etc/paguro/node-installer.state                    # what the installer has changed
journalctl -u containerd --since -10min
```

**A migration fails or rolls back:** the reason is in `status.message`
(`kubectl paguro describe <migration>`). When CRIU fails, Paguro puts
CRIU's own error lines there (for example
`criu dump: inet: Unsupported proto 262 …` – an MPTCP socket, see
[Marking workloads as migratable](#marking-workloads-as-migratable)) and,
for errors it knows, what to do. The full runc/CRIU output is in the
agent's log on the source node (`kubectl -n paguro-system logs <agent>`,
message `migration failed on the source`).

**A restored pod does not start / goes into a cold start:** paguro-runc logs
to `/var/log/paguro/paguro-runc.log` on the node, and its last error appears
in the pod events (`kubectl describe pod`). The
CRIU log of a failed restore is under
`/var/lib/paguro/restore/<migration-uid>/containers/<name>/restore-failed.log`.
