# Security

## Reporting a vulnerability

Please report vulnerabilities privately through the repository's security
advisories ("Report a vulnerability"), not in public issues. You get an
answer within a week; fixes are released as patch versions, with an
advisory once a fix is available.

Supported: the latest minor release. Paguro is pre-1.0; there are no
long-term support branches yet.

## What Paguro can do on a cluster

Paguro moves running processes between nodes, so parts of it are as
privileged as a container runtime:

| Component | Runs as | Can |
|---|---|---|
| `paguro-agent` (DaemonSet) | privileged, `hostPID`, `hostNetwork`, host root mounted for the node installer | checkpoint and restore any container on its node (CRIU), enter every pod's namespaces, change nftables/tc/routes on the node |
| `paguro-runc` (on each node) | root, called by containerd for pods with RuntimeClass `paguro` | restore a container from a checkpoint before it starts |
| `paguro-controller` (Deployment) | non-root, no capabilities, read-only root filesystem, distroless image | delete and create pods, manage EndpointSlices and Services for migrated pods, sign the agents' certificates; its webhook mutates pods marked migratable |

Anyone who controls an agent controls its node. Paguro's job is to keep it
at that: one node must not become the cluster.

## Data

A checkpoint is a workload's **complete memory and open files** – its
keys, tokens, sessions and user data – plus root filesystem changes and
`emptyDir` contents, and volumes are re-attached to another node.

- **In transit**: agent to agent over TLS 1.3 with mutual authentication.
  Each agent holds a certificate for its own node (below); a source sends
  only to the migration's target node, a target accepts a migration's data
  only from its source node. Plus a shared bearer token (Secret
  `paguro-agent-token`). With `agent.transferTLS.enabled=false` the data
  travels unencrypted – only for isolated networks.
- **At rest**: on the source under `/var/lib/paguro/dump/<migration>`, on
  the target under `/var/lib/paguro/restore/<migration>`, root-only (0700).
  Not encrypted: whoever is root on a node can read the memory of that
  node's pods anyway. The source removes its dump when the migration ends,
  the target its images two minutes later; a janitor in every agent catches
  up on anything left (agent restarts) after ten quiet minutes. Logs and
  markers stay seven days for tracing.
- Paguro sends nothing outside the cluster.

## Threat model

| Attacker | Mitigation | Remaining |
|---|---|---|
| On the node network (sniffing, spoofing, MITM) | mutual TLS with per-node certificates; the agent listens on the node's InternalIP only | – |
| A pod on the cluster (no node access) | The transfer port needs a node certificate and the token; nothing of Paguro is reachable from pods except the webhook (API server only) | NetworkPolicies cannot cover `hostNetwork` ports; restrict the transfer port at the node firewall if pods share the node network |
| A migrated workload itself | Its checkpoint is its own state; CRIU restores it with the same identity, namespaces and cgroups | CRIU parses the process state as root on the node: a CRIU vulnerability could be reached by a workload that crafts its own state |
| Root on one node (escaped container, compromised kubelet) | Owns that node's agent. Its **service account token** is held to the agent's own business by ValidatingAdmissionPolicies (`agent.restrictionPolicy`, Kubernetes ≥ 1.30): only `paguro.dev/*` annotations and gate removal on Paguro replacement pods that are unbound or on its node, only its own Node's and CiliumNodes' `paguro.dev/*` annotations, VolumeAttachments only for its own node, CSRs only for `paguro.dev/agent`, full migration status only for migrations of its node. Its **certificate** names only its node: the controller signs a request only if the requester's token is bound to a pod on that node. | see below |
| Cluster user who may create `Migration` objects | A Migration moves a pod within the cluster, never out of it; the target must be a node with a Paguro agent | Grant `paguro.dev/migrations` like `pods/eviction` – moving a pod is a disruption |
| Cluster user who may label pods/workloads `paguro.dev/migratable` | The webhook changes only pods marked migratable, and only what Paguro needs (runtime class, annotations; for replacements the restore settings) | Marking a pod migratable lets Paguro checkpoint it – its memory leaves the node during a migration |

### What a compromised node can still do

- Read every pod's specification cluster-wide (the agent needs pod
  `get/list`; environment variables in pod specs are readable – use Secrets).
- **Bind pending pods** (`pods/binding`): a Binding names only pod and
  node, so no admission rule can tell a Paguro replacement from another
  pod. A pending pod without scheduling gates could be bound to the
  compromised node, which then receives its Secrets. Workloads that must
  never run on an untrusted node should not share nodes with untrusted
  ones anyway; schedulers place pods within milliseconds, so the window is
  pods that cannot be scheduled.
- Disturb migrations it takes part in (as source or target): abort them,
  or fail the restore. A migration it does not take part in is out of
  reach.
- With `agent.preAttach.enabled`: attach any volume to **itself** (a
  VolumeAttachment names only volume and node). Off by default.
- Use the shared transfer token – it adds nothing over its certificate.

### Tokens and keys

| Secret | Holder | Rotation |
|---|---|---|
| `paguro-agent-ca` (Secret): the agents' CA, ten years | controller only | renewed 60 days before expiry; the old CA stays trusted while it is valid |
| agent node certificates, seven days | each agent, key in memory only | renewed after two thirds of the lifetime, new key each time |
| `paguro-webhook-tls`: the webhook's CA and serving certificate | controller | renewed 60 days before expiry |
| `paguro-agent-token` | every agent (environment) | delete the Secret and `helm upgrade`; migrations running during the agent rollout fail and roll back |

## Hardening options

| Value | Default | |
|---|---|---|
| `agent.transferTLS.enabled` | `true` | per-node mutual TLS between agents |
| `agent.restrictionPolicy.enabled` | `true` | admission policies for the agents' service account (needs Kubernetes ≥ 1.30; skipped on older clusters, then RBAC alone applies) |
| `agent.preAttach.enabled` | `false` | volume pre-attach (multi-attach volume types) – grants VolumeAttachment create to the agents |
| `agent.onlyLabelledNodes` | `false` | run agents only on nodes labelled `paguro.dev/enabled=true` – keep Paguro off nodes that hold sensitive workloads |

## Supply chain

Release images and the Helm chart are signed with Sigstore cosign (keyless,
by the release workflow of this repository and no other) and carry a signed
SPDX SBOM attestation:

```sh
cosign verify \
  --certificate-identity-regexp '^https://github\.com/DPicillo/paguro/\.github/workflows/release\.yaml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/dpicillo/paguro/paguro-agent:<version>
cosign verify-attestation --type spdxjson <same flags> ghcr.io/dpicillo/paguro/paguro-agent:<version>
```

Release candidates built while the repository was private are not signed:
keyless signatures are recorded in Sigstore's public transparency log.

Every release is checked with `govulncheck` (Go code, reviewed exceptions in
`hack/vulncheck-accepted.txt`) and `grype` (images: fails on fixable
vulnerabilities of severity high or above, reviewed exceptions in
`.grype.yaml`). Base images are pinned by version; Go dependencies by
`go.sum`. The node installer image ships CRIU and libraries as binaries;
their complete source is published next to it
([docs/THIRD-PARTY.md](docs/THIRD-PARTY.md)).
