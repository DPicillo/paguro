# Roadmap

Where Paguro stands and what comes next. Paguro is alpha (v0.1, API
`paguro.dev/v1alpha1`). Its primary use case: **single-replica workloads
that cannot fail over, such as game servers**, moved between nodes without
their clients noticing more than a short stall.

Ideas, measurements from other clusters and reports of what breaks are
welcome as [issues](https://github.com/DPicillo/paguro/issues).

## Where it stands (v0.1.0)

| Area | Status |
|---|---|
| Freeze | Kept IP: Cilium 0.55–0.73 s (commit gate and early hand-over), Calico 1.23–1.58 s (floor: Calico's own CNI calls). Phantom mode 0.3–0.9 s, on EKS 0.44–0.70 s. Large pods: 8 GiB rewritten at 50 MB/s took 21–33 s (what is still dirty when pre-copy ends goes into the freeze). An RWO block volume adds its detach (Minecraft world on Cinder: 10.7–13.1 s, of which the volume 6–9 s – Kubernetes' attach and detach). |
| Connections | Kept IP (Cilium, Calico): established and new TCP connections through ClusterIP, NodePort, gateways and the pod IP – 0 failures; UDP sessions kept. Phantom mode (Flannel, Antrea, AWS VPC CNI): in-cluster TCP and UDP through a Service kept, longest gap 1.5–2.7 s; connections opened through a Service during the freeze complete about 3 s after the attempt; UDP clients on the pod IP lose the session. |
| Data | RWX write-back, lock hand-over, RWO detach ordering; a 25 GiB RWO volume with an fsync'd journal: no hole; `emptyDir`s up to 10 GiB with a verified journal; NFS tested. CephFS, SMB and EFS not tested. |
| Failure safety | Commit point, rollback, rescue path; components killed during pre-copy and right after the commit: every run succeeded or rolled back cleanly. Evictions become migrations; a failed one lets the eviction through; the webhooks fail open. |
| Compatibility | Lab: Kubernetes 1.37, containerd 2.4, Ubuntu 24.04, Cilium, Calico, Flannel, Antrea; install checks on kind for 1.28–1.37. Amazon EKS 1.37: Amazon Linux 2023 nodes, AWS VPC CNI, Karpenter 1.14 (drift, deletion, spot warnings). Not supported: Bottlerocket, EKS Auto Mode, Fargate. Not run: GKE, AKS, arm64. |
| Operations | Helm-only install; `helm upgrade` during running migrations; documented uninstall; alert rules, PodMonitors, Grafana dashboard ([OPERATIONS.md](OPERATIONS.md)). |
| Security | Mutual TLS 1.3 between agents with a certificate per node; admission policies hold each agent to its node; checkpoint janitor; signed images and chart with SBOM attestations; govulncheck and grype on every release ([SECURITY.md](../SECURITY.md)). |

## Next

### Platforms

1. **Spot deadlines.** On EC2 an eviction's migration moves only if the
   interruption's deadline leaves time for it. Next: estimate the duration
   from measurements (the node's transfer rate, the pod's real memory and
   `emptyDir`s) instead of its limits and a fixed rate; an order of
   priority when not everything fits; a deadline for pre-copy itself; the
   30 s notices of GCP and Azure; a test with a real spot interruption
   (AWS Fault Injection Service).
2. **GKE and AKS** (Dataplane V2, Container-Optimized OS; Azure CNI):
   install, the regression runs, game servers, spot. On EKS: GPU nodes.
3. **Bottlerocket and EKS Auto Mode.** The kernel has everything CRIU
   needs, but the node installer stops: no `nsenter` and `ip` on the host,
   runc under Bottlerocket's own path, a read-only root, a containerd
   configuration rendered from Bottlerocket's settings. Needed: both tools
   in the bundle, the bundle under a writable path, the runtime handler
   through Bottlerocket's settings – and whether Auto Mode allows one on
   its managed nodes at all.
4. **arm64** (Graviton): multi-architecture images, CRIU for arm64 in the
   installer, a CPU baseline per architecture, and stop-and-copy where
   CRIU has no soft-dirty tracking.
5. **Node-local volumes** – measured and designed
   ([LOCAL-VOLUMES.md](LOCAL-VOLUMES.md)).
6. **Service meshes.** Istio and Linkerd sidecars and Istio's ambient
   mode are untested.
7. **Scale.** The controller caches every pod of the cluster for
   placement; nothing has run on more than five nodes.

### Networks and workloads

8. **UDP clients on the pod IP (Phantom mode)** lose the session: they keep
   writing to the old address.
9. **Agones host ports.** Players on a host port lose the connection (the
   node's address changes). Designed, not built: a forwarder on the old
   node (eBPF redirect into a GRE tunnel to the kept pod IP). Also: the
   same-name freeze (~2 s; the replacement's sandbox is created inside
   it).
10. **Calico**: the eBPF dataplane (the guards act on netfilter and
    routing), IPIP and BGP modes (the route guard is tested with VXLAN).
11. **The last tenths of a second.** On Cilium the remaining freeze is a
    serial chain – CNI 0.23 s, shim and pause container 0.15 s, container
    creation 0.07 s, restore 0.12–0.17 s. Established TCP connections stall
    ~0.9 s for a 0.6 s freeze (the peer's retransmission backoff); a packet
    from the restored side right after the restore could make the peer
    retransmit at once.
12. **Phantom mode: new connections during the freeze.** Through a Service
    they complete only with a later SYN retransmission (about 3 s after the
    attempt); connections opened to the old pod IP itself are not
    translated.
13. **Cilium's EndpointSlice behaviour, reported upstream:** the reflector
    deletes an address a slice gives up although another slice of the
    Service still lists it, and socket termination then destroys the UDP
    sockets connected to it; the ipcache entry of an address deleted with
    the newest of two endpoints that hold it; the host route of a pod CIDR
    deleted when one of two nodes holding it gives it up.
14. **CephFS, SMB, EFS**: write-back and lock tests.
15. **CI job pods** (e.g. GitLab Runner's Kubernetes executor). Needs (a)
    migrating containers with stdin attached – the runner sends the script
    over stdin – and (b) clients that stream through the Kubernetes API
    (exec/attach to the kubelet of the old node) re-attaching after the
    move: such a stream is not a pod-network flow, so Paguro cannot keep
    it. Measured: with stdin removed, the job's process was killed during
    the first pre-copy round.
16. **Unix connections in flight.** A connection that is not accepted yet
    and holds data fails CRIU's dump (GitLab: nginx → workhorse under load)
    and rolls the migration back. Before the final dump: thaw briefly
    until the listeners' accept queues are empty (sock_diag
    `UNIX_DIAG_RQLEN`), or retry the final dump.

### Testing

17. **Real clusters for every release.** The end-to-end runs (regression,
    game servers with players, node-local data, upgrades during
    migrations, Karpenter disruptions) are run by hand on a lab cluster and
    on EKS. They should run unattended, with a history of freeze times to
    catch regressions, and check RWX data too.
18. **Unit tests of the core.** Coverage: agent 28 %, restore wrapper
    25 %; Phantom datapath 63 % with its eBPF tests, which need root and a
    bpffs (16 % without – CI should run them on a privileged runner or a
    VM); controller 78 %, webhook 82 %.
19. **Soak:** days of migrations back and forth with component kills,
    watching memory, file descriptors and leftovers on the nodes.

### API

20. **Before v1beta1:** `Migration.status` carries implementation detail
    (Phantom-mode flows, network internals, per-round statistics). Decide
    what is API and what moves to events, metrics or an internal object.

### Security

19. An external review of the privileged agent, the node-to-node transfer
    and the webhooks.
20. Checkpoints hold process memory (keys, tokens) on the nodes' disks
    until they are removed – root-only, not encrypted
    ([SECURITY.md](../SECURITY.md)). Encryption at rest with a key per
    migration.

### Operations

21. `kubectl paguro support-bundle`: the migration, events, controller and
    agent logs, CRIU logs and node facts in one file. A spot interruption
    takes the source node and its agent's log with it: the agents should
    put what matters for a diagnosis into the Migration's events or status
    before the node goes.
22. A compatibility policy (Kubernetes versions, kernels, CRIU, CNIs,
    clouds) and upgrade guarantees; the preflight already refuses what it
    knows cannot work.
23. A documentation site with quick starts (k3s, EKS).

## Done in v0.1.0

- Kept IP wherever the CNI can move the address (Cilium, Calico); Phantom
  mode elsewhere, the fastest mode where it applies.
- Commit gate (DRA) and early hand-over on Cilium; UDP with a kept IP and
  in Phantom mode; Calico.
- Agones GameServers; `emptyDir`s during pre-copy; NFS; lazy restore.
- AGPL-3.0-only, third-party notices and the CRIU source image; TLS
  between agents with per-node certificates; admission policies; upgrades
  during migrations; alert rules and dashboard; Kubernetes 1.28–1.37.
- Evictions become migrations, at most three per node at a time, waiting
  for a node Karpenter launches; spot interruption deadlines on EC2; a
  startup taint for new nodes.
- Amazon EKS with Amazon Linux 2023 and the AWS VPC CNI; Karpenter drift,
  deletion and spot warnings.
