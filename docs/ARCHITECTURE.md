# Paguro – Architecture

Paguro migrates running Kubernetes pods to another node together with their
**RAM state**, **open files on PVCs**, **root filesystem changes** and their
**established connections** – keeping the pod IP where the CNI can move it,
translating the old address otherwise (Phantom mode).

## Components

| Component | Runs as | Responsibility |
|---|---|---|
| `paguro-controller` | Deployment (2 replicas, one leader; every replica serves the webhook) | CRD `Migration`, orchestration, admission webhook (intercepts the replacement pod), backend keeper, mutation audit |
| `paguro-agent` | DaemonSet (privileged, hostPID, hostNetwork) | CRIU dumps (pre-copy rounds, final dump), node↔node transfer, rootfs/emptyDir deltas, restore staging, Phantom-mode translator (eBPF), route watch |
| node installer | init container of the agent | prepares a node: CRIU, nftables, `/etc/criu/runc.conf`, `paguro-runc`, containerd runtime handler `paguro`; undoes exactly that on uninstall |
| `paguro-runc` | OCI runtime wrapper (RuntimeClass `paguro`) | replaces `runc create` with `runc restore` on the target node – kubelet and containerd see an ordinary container start; disables MPTCP in every Paguro sandbox |
| `kubectl-paguro` | CLI plugin | `migrate`, `drain`, `list`, `describe` |

Installation is one Helm chart (`deploy/helm/paguro`, [INSTALL.md](INSTALL.md)).

## Flow of a migration

```
 Source (node A)                          Target (node B)
 ───────────────                          ───────────────
 0 Preflight (controller): CPU features B ⊇ A, capacity, volumes, network
   mode (keep IP / Phantom / generic), MPTCP check (agent)
 1 Pre-copy rounds 1..n ── memory pages ──▶ /var/lib/paguro/restore/<uid>/
   (app keeps running; soft-dirty tracking; CPU throttled if it does not
   converge) and rootfs/emptyDir deltas
   New IP only: the replacement pod is created now; its sandbox (CNI ADD)
   is up before the source freezes
   Keep IP on Cilium: the replacement's pool generation is created now and
   its /32 handed to node B ahead of the freeze (the source's endpoint keeps
   the address); the replacement pod waits behind a scheduling gate
   Keep IP with the commit gate: the replacement is bound to B and held by
   the gate (a DRA claim) right before kubelet creates its sandbox
 2 FREEZE: new SYNs dropped, pending handshakes accepted (drain), shield
   up, pod paused; final dump (dirty pages, TCP repair state, network
   locked); Phantom mode: harvest the frozen pod's connections
   Keep IP on Cilium (early hand-over): the source tells B it is paused;
   the gate lets the replacement go and its sandbox is created while the
   dump runs (shielded; the restore still waits for READY)
 3 COMMIT: one status patch – phase Frozen, frozenAt (, connections)
   Before it every failure rolls back (source thawed); after it there is
   no rollback, the replacement is the workload
 4 Final images and deltas ─────────────▶ restore staging
 5 Controller deletes the source pod (again on every later step until it
   is gone); endpoint bridge (kept IP) or backend keeper (Phantom mode); RWO
   volumes detach/attach (or were pre-attached)
 6 Keep IP: the replacement pod is created now (webhook: nodeName=B,
   runtimeClass=paguro, restore id, IP adapter annotations)
 7                                          paguro-runc: sandbox with the
                                            RST shield up, rootfs delta,
                                            new IP: old addresses on lo,
                                            UDP servers held (answer only
                                            peers that wrote first, 30 s),
                                            runc restore (lazy pages for
                                            large RSS), shield down
 8 Phantom mode: target node programs first (inbound rules pending until the
   restore), then every peer node; connections continue on the new IP
```

Freeze = steps 2–7 (frozen to restored). Pre-copy reduces step 2 to the
pages written since the last round; with a new IP, the CNI's work (step 1)
happens before the freeze.

## Where it is in the code

For a maintainer: each step of the flow above and the file that does it.

**Controller** (`internal/controller`): a state machine over
`Migration.status.phase`; `reconciler.go` dispatches by phase.

| Phase | Function | File |
|---|---|---|
| Pending → Preflight | `start`, `preflight`/`runPreflight` (owner, volumes, network mode, target node) | `reconciler.go`, `preflight.go` |
| PreCopy | `watchPreCopy`; warm replacement `ensureEarlyReplacement`; sticky pools | `reconciler.go`, `early.go`, `pools.go` |
| Frozen | `beginCutover`/`beginEarlyCutover`: bridge or keeper, source deletion | `cutover.go`, `bridge.go`, `keeper.go` |
| CuttingOver | `continueCutover`: wait for or create the replacement | `cutover.go` |
| Restoring | `watchRestore`, `succeed`, volume tracking | `restore.go` |
| Aborting | `watchAbort`, `undoEarlyReplacement`, `reannounce` | `restore.go`, `early.go`, `reannounce.go` |
| Succeeded / RolledBack / Failed | `cleanupTerminal`: `releaseSource` once (`status.releasedAt`), then bridge, keeper, finalizer | `terminal.go` |

Status writes: `transition` (phase changes), `patchStatus` (locked),
`patchStatusUnlocked` – `status.go` says which for what. The webhook
(`internal/webhook`) turns the owner's new pod into the restore target;
`internal/placement` chooses target nodes (pure functions).

**Agent** (`internal/agent`): `agent.go` Reconcile starts one job per
role and remembers per migration what it did (`migState`).

| Step | Function | File |
|---|---|---|
| Source: start, pre-copy, waits for the target | `execute` → `start`, `copyUntilReady`, `preCopy`, `awaitTarget` | `source.go`, `source_precopy.go` |
| Source: freeze, final dump, work alongside | `freezeAndDump`, `alongsideDump`, `finalDump`, `freeze`/`thaw` | `source.go`, `source_freeze.go` |
| Source: commit, transfer, network release | `commitAndSend`, `commitResolved`, `sendFinal`, `releaseSourceNetwork` | `source.go`, `agent.go`, `source_transfer.go`, `source_release.go` |
| Transfer protocol, both ends | `Server`, `Client`; rounds folded into the base in the background | `transfer.go`, `roundqueue.go`, `transfertls.go` |
| Target: preparation, commit gate, restore watch | `targetJob.prepare`, `commitGate`, `watchRestore`, `rescue` | `target.go`, `dragate.go`, `agent.go` |
| Address hand-over (Cilium, Calico) | `handover.go`, `cilium.go`, `ciliumroutes.go`, `cnidel.go`, `routeguard.go`, `natguard.go` | |
| Phantom mode | manager and state, programming, routes, release | `phantom.go`, `phantom_program.go`, `phantom_routes.go`, `phantom_release.go`, `internal/phantom` |
| Restarts and shutdown | resume after the commit, drain on SIGTERM, janitors | `resume.go`, `shutdown.go`, `statejanitor.go`, `janitor.go` |

**Wrapper** (`cmd/paguro-runc`): `main.go` parses runc's arguments and
passes everything through except `create` of a restore target;
`restore.go` (`restoreContainer`, a `restorer` with one method per step)
does the restore; `runc.go` calls the real runc. The checkpoint's layout on
disk is in `internal/layout`.

**Tests:** `make ci` (format, headers, vet, staticcheck, unit tests,
generated files, chart); `hack/version-matrix.sh` (Kubernetes 1.28–1.37 on
kind); behaviour on real clusters with the lab's suites, which are not
part of this repository (see ROADMAP.md).

## Network modes

| Mode | IP | Connections | Mechanism |
|---|---|---|---|
| keep IP: `cilium` | kept | all | a dedicated `CiliumPodIPPool` with one /32 per migratable pod (sticky IP), new pool generation per migration – created in pre-copy and allocated to the target ahead of the freeze; the replacement waits at the commit gate (a DRA claim, right before kubelet creates its sandbox) and is let go when the source is paused (early hand-over), so its sandbox is created while the final dump runs |
| keep IP: `calico` | kept | all | `cni.projectcalico.org/ipAddrs` on the replacement; the replacement waits at the commit gate until the source agent has released the frozen pod's network (it runs the CNI DEL itself, from containerd's cached attachment, before stopping the sandbox), then calico-ipam hands the /32 to the target node; a route guard prevents the routing loop while Felix's routes converge, and every node guards the NAT bindings of the address (Felix flushes them cluster-wide) |
| `phantom` | new | in-cluster kept | eBPF 5-tuple translator on the nodes involved: OLD↔NEW for exactly the migrated connections ([PHANTOM-MODE.md](PHANTOM-MODE.md)); peers outside the cluster are closed |
| `generic` | new | closed at once | restored with `--tcp-established`, then aborted (`SOCK_DESTROY`) so the app reconnects immediately |

`spec.network: Auto` keeps the IP when both nodes run a CNI that can move
it, otherwise uses Phantom mode when every node supports it, otherwise generic.
The CNI is detected per node from its active CNI configuration
([CNI.md](CNI.md)). The old addresses stay on the restored pod's `lo`
(`arp_ignore=1`), so sockets bound to them can be restored.

## Safety properties

* **Commit point.** Everything before the commit patch can roll back: the
  source is thawed, the warm replacement deleted. The commit itself only
  succeeds while the migration is still in pre-copy (the object's
  resourceVersion is its precondition), so an abort the controller decided
  meanwhile always wins. Deleting a migration after the commit finishes the
  cutover first when a replacement exists – it may already be restoring.
* **No half-finished dumps.** A CRIU run is never interrupted: killing it
  would leave its parasite code in the tasks, and a final dump that ends
  after a thaw freezes the cgroup again. An abort waits for the running dump
  before it thaws (measured: abort in the middle of a 3 GiB final dump –
  source thawed and running).
* **Agent restarts.** An agent restarted during pre-copy or the final dump
  reports the lost job at once, so the abort – a thaw from runc's state,
  including the CPU quota that auto-converge lowered – does not wait for the
  migration's timeout (measured: rolled back 5 s after the restart). After
  the commit the frozen state exists only in the dump directory: the source
  keeps the metadata it sends next to it, and a restarted agent sends the
  rest – never again for a container the target may already be restoring.
  The target enforces that itself: once a container is READY it refuses
  new images, rootfs data and a FAILED marker for it (409), which also
  covers a restart between READY and the source's own record of it.
  Measured: source agent deleted in the middle of a 3 GiB transfer, the
  migration completed with its memory state, no cold start. The target
  waits as long as data keeps arriving; 100 s of silence mean a cold start.
* **No split brain.** The target restores only on READY, and READY is
  sent only after the commit; a replacement cannot run a copy of a pod that
  may still be thawed. The final data itself travels in parallel with the
  commit (the commit's API round trip is not part of the freeze); after a
  failed commit no READY follows and the target discards it.
* **A replacement never runs next to its source.** After a rollback the
  target agent leaves an ABORTED marker; a replacement waiting in the
  restore wrapper fails its container creation instead of waiting for data
  or cold-starting. A migration does not reach Succeeded while its source
  pod still exists without a deletion timestamp (the delete at the commit
  is repeated on every later step – found after a controller rollout lost
  it).
* **Rollback after an early hand-over** (Cilium). The replacement's
  endpoint may already have taken the address. Cilium deletes the
  address's ipcache entry when that endpoint goes, although the source's
  endpoint still holds it, and the address falls back to its pool's CIDR
  with the world identity. After the replacement's endpoint is gone the
  controller re-announces the source's CiliumEndpoint (a changed order of
  its identity labels makes every agent read it again). Measured with an
  injected fault: identity right throughout, route back at the source,
  players saw no error.
* **Rescue.** After the commit the replacement is the only copy: a failed
  restore is retried (the checkpoint is kept) and falls back to a cold
  start with a reason in the status.
* **NAT bindings survive the CNI's conntrack flush** (keep-IP mode,
  internal/ctguard). A NodePort/LoadBalancer client (externalTrafficPolicy
  Cluster) is masqueraded on its entry node to an address that depends on
  the way to the pod – the node IP while the pod is local, the tunnel
  device's while it is remote. Calico's Felix flushes every conntrack
  entry of a workload IP when the endpoint disappears and when it appears;
  NATed afresh, the client's next packet got the other address, and the
  restored socket answered with a reset. The source and target agents
  record the pod's NATed entries at the freeze and re-install what goes
  missing or comes back with another binding until shortly after the
  restore (ctnetlink with CTA_NAT_SRC/DST; untranslated reply tuple, liberal
  window tracking). Measured on Calico: NodePort client 0 lost in both
  directions.
* **A sticky address never leaves the cluster's routes** (keep-IP on
  Cilium, CiliumHooks.Hold). Cilium's load balancer decides per packet
  whether a backend is a cluster endpoint (into the tunnel, SNAT to the
  router IP) or outside the cluster (uplink, SNAT to the node IP), and
  rebinds a NodePort/LoadBalancer connection when that changes. Releasing
  the source's address freed the sticky pool's only CIDR, and until the
  target's endpoint appeared – seconds while an RWO volume moves – the
  entry node rebuilt the client's NAT for the uplink; the restored socket
  then answered with a reset. The source agent now holds the pool's CIDR on
  its node (a pending IPAM request under its own owner) before it releases
  the address: the address keeps pointing at the frozen source node until
  the target's endpoint, which takes precedence, is there; the hold ends
  5 s after the restore. Measured: browser through a NodePort on an
  uninvolved node, 11.5 s freeze with an RWO volume move – same TCP
  connection, no packet through the uplink.
* **The node's routes to a kept address** (Cilium,
  internal/agent/ciliumroutes.go). Every Cilium agent routes each pod CIDR
  any node holds through `cilium_host`, keyed by the prefix alone; while an
  address moves, two pool generations hold the same /32 on two nodes, and
  releasing the first – the source's old generation after a migration, the
  prepared one after a rollback – deleted the route on every node, the
  pod's own included, for 60–130 s. Pod and Service traffic does not use
  these routes; the host does: kubelet's probes of a just-migrated pod
  failed (found when a GameServer died of its liveness probe after a
  rollback). Each agent's route keeper restores the route of every /32 a
  CiliumNode still holds for a Paguro pool, on the deletion event.
  Measured on all five lab nodes: back within 0.5–4 ms after migrations
  and rollbacks, host pings losing only the freeze.
* **New connections and UDP flows during the hand-over**
  (internal/controller/bridge.go). With a kept IP the pod's Services keep
  the address as a ready endpoint throughout (an EndpointSlice bridge from
  before the source's deletion until the replacement is ready): a new
  connection's SYN is dropped by the shield and answered after the
  restore. Cilium (1.20) reads EndpointSlices in 500 ms batches, deletes an
  address a slice gives up even while another slice lists it, and destroys
  every UDP socket connected to a backend that is deleted or not active.
  So the address may never vanish for a moment: the bridge is touched every
  50 ms until the source has left the Service's own slices and the kept
  address is ready there again (a replacement under the source's name –
  StatefulSet, GameServer – is listed with it, not ready, while it
  restores), and the own slices every 50 ms around the bridge's deletion,
  so that both changes always share a batch. Only on Cilium – kube-proxy
  applies every slice event as it comes, so elsewhere a touch would only
  load the API server and every watcher – and capped at 100 touches per
  second for all migrations together (a drain of many nodes touches each
  slice less often). No selector-less keeper Service with a kept IP: its
  deletion deleted a backend of the address and destroyed game clients'
  sockets. The shield also drops the target's ICMP "port unreachable"
  before the restore (connected UDP sockets would fail with ECONNREFUSED).
  Measured: 0 failed of ~5,800 new TCP connections and 625 of 625 new UDP
  players, no UDP socket error, via ClusterIP, NodePort, pod IP and
  gateways. Phantom mode (PHANTOM-MODE.md, section 9): the bridge lists
  the new address; through a NodePort nothing fails (≤ 1 s) for TCP; a
  connection opened through a Service during the freeze is handed back to
  the Service after the restore and completes about 3 s after the attempt
  instead of hanging; one opened to the old pod IP itself is not
  translated. UDP through a Service continues ("UDP servers"); UDP clients
  that write to the old pod IP directly lose the session.
* **Calico: no routing loop, no new NAT binding** (internal/agent/routeguard.go,
  internal/ctguard). The replacement's endpoint is published before Felix on
  the target has its local route; the block owner and the target sent the
  address back and forth until the TTL ran out (ICMP time exceeded →
  EHOSTUNREACH for new connections). From the commit until 5 s after the
  restore, source and target drop transit packets for the address (nftables,
  forward hook) – clients retransmit. Felix flushes the conntrack entries of
  the address on every node when the source's endpoint goes; NodePort
  clients were masqueraded afresh and reached the server from a new port.
  Every node records the NAT bindings of the address before the freeze and
  re-installs flushed ones from conntrack events within milliseconds (TCP
  and UDP streams; wrongly bound entries are deleted by their exact reply
  tuple). Measured: 0 failed connections, no UDP session reset.
* **No connection left in an accept queue.** CRIU cannot dump a listener
  with connections waiting to be accepted ("In-flight connection"). Before
  the pause the shield first drops only new SYNs and waits until the
  handshakes in progress are finished and accepted (10–18 ms measured, at
  most 200 ms; then the dump may fail and the migration rolls back).
* **Fail fast instead of hanging.** CRIU blockers are found before the
  freeze (MPTCP sockets); CRIU errors are reported with CRIU's own message;
  connections that Phantom mode cannot keep are closed, or – when a node's
  routes to an old address disappear – reset via the backend keeper
  instead of hanging until a TCP timeout.
* **Webhook fails open.** A Paguro outage never blocks pod creation; pods
  created while the webhook was unreachable are reported (`NotMutated`
  events, `paguro_unmutated_pods`).

## PVC semantics

* **RWO (Cinder, EBS …)**: the source's unmount (after the freeze) flushes
  the page cache; attach on B only after the detach. Open file descriptors
  point to the same inodes again after the restore, because runc redirects
  the bind mounts to the new sources by target path (`ext-mount-map`).
  During pre-copy the target agent attaches volumes whose type allows
  multi-attach (Cinder `multiattach`, EBS io2) to the target in advance –
  measured on Cinder: detach 3.2 s and attach 13.1 s would otherwise sit in
  the freeze; the volume is mounted on the target only after the source's
  unmount. Other volumes attach after the detach.

  What stays in the freeze, measured with a Minecraft world (5 GiB,
  Cinder multi-attach, pre-attached), freeze 13.0–13.1 s of which the
  volume 9.3 s:

  | step | time | who |
  |---|---|---|
  | frozen containers stopped, kubelet unmounts | 1.1 s after the commit (3.0 s before the source agent stopped them itself) | Paguro, kubelet |
  | kubelet reports the volume as no longer in use (`node.status.volumesInUse`) | 1.7–3.9 s: the next node status update (`nodeStatusUpdateFrequency`, 4 s in the lab, 10 s by default) | kubelet |
  | detach from the source | 5.0 s | attach/detach controller, Cinder |
  | attach to the target (already attached) | 0.55–0.6 s | attach/detach controller |
  | mount, sandbox, restore | ~2 s | kubelet, Paguro |

  The attach/detach controller attaches an RWO volume to a second node
  only once the first detach has finished, whatever the volume type
  allows; that wait is the price of a block volume. Workloads with a short
  freeze budget keep their state on RWX storage or in `emptyDir`.
* **RWX (NFS, CephFS, SMB, FUSE)**: no detach; the target mounts the
  volume while the source node still has it mounted. Before the final dump
  the source writes the frozen pod's page cache back (syncfs). On a shared
  filesystem that step is mandatory: if it fails or takes longer than 30 s
  the migration is rolled back – otherwise the restored process could read
  stale data, or the source node could later write old data over its
  writes. No pre-attach: Kubernetes attaches RWX volumes to several nodes at
  once, and drivers that attach nothing (CSIDriver `attachRequired: false`,
  e.g. NFS) are skipped – waiting for an attach that never comes once
  delayed pre-copy by 90 s. Measured (NFS, csi-driver-nfs): a process
  appending to an open file every 20 ms without fsync, 6 moves – every
  record exactly once and in order, no NUL bytes, no restart; write-back
  3–4 ms, 3 s per migration. (On NFS the kernel client also writes a file
  back when its attributes are read, which CRIU's dump does for every open
  file – a build without Paguro's write-back stayed correct there; other
  filesystems do not all behave like that.)
  Files deleted while open (NFS keeps them as `.nfsXXXX`): the final dump
  of a pod with an RWX volume runs with `--link-remap`, CRIU links such a
  file under a stable name next to it, and the restore opens and removes
  that name. CRIU removes the links again at the end of a dump that leaves
  the process running, so the source agent creates them anew from the
  dump's images while the frozen process still holds the file
  (`internal/agent/source_remap.go`); a rollback removes them. Measured:
  Minecraft with its world on NFS (a JNA library extracted to `/data` and
  deleted after loading) rolled back on every attempt before; now 2.5–2.9 s
  freeze, world intact after a cold restart from NFS.
* **File locks on shared filesystems** (internal/agent/locks.go). CRIU
  takes a process's locks again on restore – on NFS the lock lives on the
  server, and the frozen source still held it: the restore waited 30 s for
  the server. The source now ends its processes before READY when they
  hold such locks (after the commit, once the pod is terminating and the
  target sandbox is up); the restore gets the lock at once. A process on
  another node can take the lock in the ~0.2 s in between; if it keeps it,
  the restore waits.
* **Images** are pinned to the digest the source node runs (internal/images):
  a tag may mean another image on the target node, and a restored process
  must find exactly the files it was started with.
* **emptyDir**: sent during pre-copy, alongside the memory rounds, with a
  manifest of what was sent (size, mtime, inode, owner, mode); the target
  unpacks it next to the checkpoint. The freeze carries only new and
  changed entries and whiteouts for deleted ones – plus files the pod has
  mapped shared and writable, and files written within a second of the
  base (a second write in the same timestamp tick would leave size and
  mtime alone). The wrapper moves the base into the new pod's emptyDir by
  rename and applies the delta. Measured: a Minecraft Bedrock server keeps
  its 233 MB binary in its data directory – the freeze went from 5.1 s
  (all 366 MB packed and sent inside it) to 0.7–0.8 s.
* **The pod's own /dev/shm** (containerd's tmpfs of the sandbox, shared by
  the containers, not a volume): packed in the freeze and unpacked into the
  replacement's before the restore. For CRIU it is a mount from outside,
  whose files it expects to find again – PostgreSQL's dynamic shared
  memory, Ruby's metrics files (GitLab on EKS: the restore failed on
  `dev/shm/gitlab/sidekiq/…`, the pod cold-started). Small by nature
  (containerd's default: 64 MiB); an emptyDir at /dev/shm travels as an
  emptyDir.
* **hostPath**: rejected (the data stays on the node).

## Cross-system

* **Different CPUs** (internal/cpufeat): a process picks its code paths
  when it starts – glibc chooses its string functions by CPUID (on CPUs
  with TSX, variants that execute XTEST), Go uses ADX and BMI2 for crypto,
  the JVM compiles for the AVX level it finds. Moved to a CPU without those
  instructions it dies with SIGILL at the next call; no checkpoint tool can
  repair that afterwards. Paguro does what VM live migration does with CPU
  models: a process that never saw a feature cannot depend on it.
  * The webhook gives every migratable pod a **CPU baseline** when it is
    created (annotation `paguro.dev/cpu-baseline`): the features all nodes
    with an agent share (`cpuBaseline: auto`), or a fixed x86-64 level for
    clusters whose node types change. A replacement keeps the source's
    baseline.
  * paguro-runc starts the containers with the **runtimes limited to it**:
    `GLIBC_TUNABLES=glibc.cpu.hwcaps=-…`, `GODEBUG=cpu.…=off`,
    `OPENSSL_ia32cap`, `JAVA_TOOL_OPTIONS` (behind
    `-XX:+IgnoreUnrecognizedVMOptions`), `DOTNET_Enable…=0`,
    `ATEN_CPU_CAPABILITY`. Values the image or the pod set are extended,
    not replaced. Only features this host has and the baseline lacks are
    switched off – on a homogeneous cluster nothing changes.
  * Preflight compares only features a process can use (no kernel,
    hypervisor or mitigation flags, no performance hints like `erms`) and
    accepts a target that lacks only features outside the pod's baseline.
    Pods without a baseline need a target that has every feature of the
    source CPU; `cpuPolicy: Ignore` overrides the check.
  * Measured (lab, Broadwell → Haswell guests, Python on glibc 2.41): with
    the baseline the process continued, memory intact, freeze 326 ms;
    forced without it, it died right after the restore with SIGILL – on
    `xtest` in glibc's `_rtm` string functions.
  * A pod never moves to another CPU architecture (amd64 ↔ arm64), not
    even with `cpuPolicy: Ignore`; arm64 nodes publish their `Features`.
  * Not covered: code that queries CPUID itself without a runtime switch
    (V8/Node.js, Rust's feature detection, hand-written assembly, numpy's
    dispatch – numpy refuses to start when a feature it was built with is
    disabled), and binaries compiled for a higher level than the baseline
    (they cannot run on such a node at all, so a scheduling constraint
    already keeps them away, and Paguro respects it). Differences in
    AVX-512 are untested (no such CPU in the lab).
* **Clocks**: pods under the RuntimeClass get their own time namespace, so
  monotonic clocks continue after the move.
