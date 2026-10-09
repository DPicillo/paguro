# Paguro Phantom network mode

Status: implemented and in use – `spec.network: Phantom`, or `Auto` when the
CNI cannot keep the pod's IP. Tested in a network-namespace model of a
three-node cluster with real CRIU checkpoints, on kubeadm clusters with
Cilium, Calico, Flannel and Antrea, and on Amazon EKS with the AWS VPC CNI.
This document is the design: how the translation works, what survives and
what does not. Users need sections 1, 5 and 9.

---

## 1. Positioning: the fastest mode, and the one for every CNI

Paguro's default and expected behaviour is that the migrated pod **keeps
its IP**: Cilium (sticky `/32` pools) and Calico (`ipAddrs`). That is what
users expect, and it preserves *every* kind of traffic, including flows to
and from outside the cluster.

Phantom mode exists for clusters where the IP **cannot** move:

* AWS VPC CNI (especially with prefix delegation: the IP belongs to an ENI
  prefix of the old node),
* CNIs without static/sticky IP support (flannel, kindnet, Azure CNI
  overlay, GKE dataplane v1 ...),
* Cilium/Calico setups where the operator does not allow sticky pools.

| Selection | When |
|---|---|
| **automatic** | `spec.network: Auto` (default): the CNI cannot keep the pod's IP on the target node, and every node runs an agent that reports Phantom capability (`paguro.dev/phantom: available`). |
| **explicit** | `spec.network: Phantom` on the Migration (`kubectl paguro migrate --network Phantom`), or the annotation `paguro.dev/network: phantom` on the pod (template). Pods with that annotation get no sticky IP under Cilium. An unknown value is refused (webhook and preflight), never read as Auto. |
| **refused** | Pods with a sticky IP (Cilium): once the source is gone Cilium stops routing the old /32, so NodePort and host-network connections could not be kept (8.2) – keeping the IP keeps all of them. |
| **closed flows** | Flows Phantom mode cannot keep (peers outside the cluster, section 8) are aborted in the restored pod right after the restore, so that the application reconnects at once. |

**The fastest mode.** Phantom mode turned out to be the *fastest* mode, not
just the fallback. With a new IP the replacement pod's
sandbox can be created while the source still runs; the source freezes
only once it is up (`status.source.readyToFreezeAt` →
`status.target.sandboxReadyAt`). Pod creation, admission, kubelet and the
CNI's work all happen before the freeze. The IP-keeping modes cannot do
that: the CNI can only hand over the IP after the source released it.

| Lab measurement | Freeze | Client gap |
|---|---|---|
| Cilium, sticky IP (1 GiB) | 1.0–1.5 s | 1.5–3 s |
| Calico, `ipAddrs` (128 MiB) | 1.9–3.7 s | up to 6.4 s |
| **Phantom mode on Cilium (1 GiB)** | **0.50–0.69 s** | **0.63–0.71 s** (one 1.48 s) |
| **Phantom mode on Calico + kube-proxy (128 MiB)** | **0.38–0.50 s** to the worker, 1.0–1.4 s to the busy control-plane node | **max 1.5 s** |

(Measured when Phantom mode was integrated. The IP-keeping modes have
become faster since – commit gate and early hand-over: Cilium 0.55–0.73 s,
Calico 1.23–1.58 s, [CNI.md](CNI.md).)

The IP-keeping modes remain the choice when a connection *needs* the IP:
peers outside the cluster that see the pod IP (routable pod IPs, NLB IP
targets) and flows the old node masqueraded (with an egress gateway).

### What Phantom mode keeps

| Connection | Kept |
|---|---|
| In-cluster pod↔pod TCP | yes (tested) |
| Host-network clients (kubelet, hostNetwork pods), also on the target node itself | yes (tested) |
| Clients from outside via NodePort/LoadBalancer (`externalTrafficPolicy: Cluster`), kube-proxy | yes (tested, including collision handling) |
| Same via Cilium's kube-proxy replacement | while Cilium still routes the old address (section 8.2) |
| Pod → ClusterIP via kube-proxy DNAT (both directions) | yes (tested) |
| Migrated pod → external endpoint behind SNAT | no in plain Phantom mode; anchor design ([section 8](#8-external-traffic)) |
| UDP | connected UDP flows (datapath tested); UDP servers (game servers, QUIC) for clients that come through a Service, NodePort and LoadBalancer included ([below](#udp-servers)); not clients writing to the pod IP directly |
| IPv6 | datapath implemented and tested (TCP+UDP); harvest/plan dual-stack |
| Kernel | TCX (6.6+) preferred, legacy clsact fallback (tested) |
| Translation granularity | **per 5-tuple**: recycled old IPs and new connections are never touched |
| New connections that reuse a migrated flow's 4-tuple | prevented (port reservation + conntrack placeholder, tested) |
| Mapping lifetime | exact, from the restored pod's socket table |

---

## 2. Terms

* **OLD** – the pod IP before the migration. The restored sockets keep it.
* **NEW** – the IP the CNI gives the replacement pod.
* **inside view** – addresses as a socket sees them (migrated pod: OLD;
  its peers: OLD as the remote).
* **wire view** – addresses on the network and in the CNI's datapath:
  only NEW. **The CNI never sees OLD** for a migrated flow.
* **flow** – one connection of the migrated pod at freeze time:
  `(proto, OLD:port, remote)` from the pod's socket table, plus the real
  peer on the wire if the old node NAT'ed it (`Wire`).

## 3. Model: an exact, bidirectional 5-tuple translator

The datapath knows no pods, IPs or migrations. It has two hash maps:

```
xl_out[{scope, inside tuple of a packet LEAVING an endpoint}] = wire tuple
xl_in [{scope, wire tuple of a packet ARRIVING at an endpoint}] = inside tuple
```

and programs that sit where packets leave or enter an **endpoint**. An
endpoint is either a pod network namespace (scope `pod`) or the host
network stack of a node (scope `host`). For every flow, the control plane
installs one `out`/`in` pair at each end:

```
            migrated pod (target node)                     peer endpoint
  inside:   OLD:7000 <-> C:40000                           C:40000 <-> OLD:7000
  out rule  OLD:7000->C:40000  => NEW:7000->C:40000        C:40000->OLD:7000 => C:40000->NEW:7000
  in rule   C:40000->NEW:7000  => C:40000->OLD:7000        NEW:7000->C:40000 => OLD:7000->C:40000
  wire:                 C:40000 <-> NEW:7000   (only NEW is ever on the network)
```

Everything that is not an exact hit is passed on unchanged (`TCX_NEXT` /
`TC_ACT_UNSPEC`): the CNI's programs that follow see exactly what they
would see without Paguro. The only packets a program ever drops are inbound
packets of a flow that is explicitly marked *pending* (restore not finished).

Rules can also rewrite ports (needed when the old node DNAT'ed the flow, see
[ClusterIP from the migrated pod](#6k-migrated-pod--clusterip-kube-proxy)).

### 3.1 Why per 5-tuple and not per IP (decision)

Per-IP translation ("rewrite every packet to OLD into NEW, cluster-wide")
is simpler but wrong in three ways that matter for "connections must not
break":

1. **IP reuse.** Once the old pod is gone, IPAM may give OLD to a new pod.
   Per-IP rewriting then hijacks all traffic for the new owner, for as long
   as the mapping exists. Per flow, a recycled OLD is never touched: only
   the exact 4-tuples that existed at freeze time are translated
   (`TestTranslationSockets`: a new connection to OLD is *not* translated).
2. **New connections to NEW.** After the migration the EndpointSlice
   contains NEW, so new clients connect to NEW natively. A per-IP reverse
   rule on peers ("source NEW → OLD") would rewrite *their* replies and
   break them. Per flow, only replies of migrated flows are rewritten.
3. **Lifetime.** Per IP there is no natural end: a mapping is needed "as
   long as some old connection might exist". Per flow, the set is finite
   and known, and garbage collection is exact ([section 10](#10-lifetime-and-garbage-collection)).

Cost: the flows must be harvested at freeze time and distributed, and
*new* connections to OLD after the migration are not preserved — which is
correct Kubernetes semantics (OLD no longer belongs to the pod; clients
reconnect through the Service and get NEW).

Rejected variant: per-IP rewriting with socket-aware disambiguation
(`bpf_sk_lookup_tcp` in the peer netns to decide whether a reply belongs to
a socket connected to OLD or NEW). It fixes (2) but not (1) or (3), needs
netns ids for host-side placement, and cannot help host-scope/NAT flows.

### 3.2 Wire-tuple collisions and reservation (decision)

A migrated flow appears on the wire as `C:p <-> NEW:L`. The client side of
that flow (here C) can open a **new** connection with the very same
4-tuple: its socket of the old flow is connected to `OLD:L`, so the kernel
considers `C:p` free towards `NEW:L` (`connect()` autobind shares a port
across different 4-tuples). Both connections are then indistinguishable on
the wire. With *k* migrated flows from one client to one port the chance
per new connection is roughly k/28 000 — connection pools that reconnect
through the Service after the migration hit it within minutes.

The benchmark run into this by accident (a restricted ephemeral range made
every new connection reuse a migrated port, and all of them hung); the
negative controls reproduce it deterministically
(`TestWireTupleReservation`, `e2e.sh -no-reservations`: the new
connections never complete).

Fix: make the collision impossible at its source.

* **Sockets** (peer pods, host-network clients, the migrated pod's own
  outbound flows): the client-side port of every migrated flow is added to
  `net.ipv4.ip_local_reserved_ports` *in the client's network namespace*.
  `connect()` autobind never picks a reserved port; explicit `bind()` (as
  CRIU does on restore) still works. Which side is the client follows from
  the pod's listening sockets at harvest time (`Flow.Server`).
* **netfilter SNAT** on a NodePort/LoadBalancer entry node (the port was
  chosen by masquerade, not by a socket): a **placeholder conntrack entry**
  for the wire tuple. `nf_nat` treats the tuple as taken and picks another
  port. The placeholder never sees a packet of the migrated flow, because
  the host-scope programs translate outside netfilter's view (egress after
  POSTROUTING, ingress before PREROUTING).
* **No placeholder for a connection that is on the wire as itself** (the
  pod came back to the address the connection was opened to, 3.3): the
  connection's own conntrack entry holds the tuple – kube-proxy's NodePort
  entry has exactly that reply tuple, and the kernel refuses a second entry
  with it. A placeholder that cannot be created because another entry holds
  the tuple in its reply direction counts as reserved; nf_nat does not
  allocate that tuple either. (Measured on EKS before this rule: the failed
  placeholder failed the NodePort entry node's whole programming.)

Evidence (e2e, with reservation): new connection from the same pod got port
33037 while the migrated flow holds 33036; a second outside client with the
same source port 45042 was masqueraded to 42679. All four connections kept
running. Without reservation neither new connection completed.

### 3.3 Chained migrations and addresses that come back

A restored socket keeps its local address on every later hop. After X → Y →
Z the pod holds connections bound to X (opened before the first hop), to Y
(opened during it) and new ones on Z. Every hop translates each flow from
its **own** local address to the new IP (`PlanFlows`), on the target and on
every peer; `status.sourcePodIP` is only the address of the hop before. A
peer's rules are keyed by the peer's inside tuple, which does not change
from hop to hop, so the new hop's rules replace the previous hop's and carry
the new hop's id. Releasing the previous hop by owner then removes only what
nothing replaced: its reply rules for the intermediate address that is gone.
The same holds when the previous hop reports single flows ended
(`deadFlows`) – which it may do for connections the new hop took over, when
their sockets go away with the new hop's source: a node removes a reported
flow's rule only while the installed rule under that key still carries the
previous hop's id (`Translator.RevertOwned`). Node-wide maps make this
matter on the pod's own nodes too: after X → Y → Z → Y the target of the
third hop holds the first hop's keys.

When the pod comes back to an address one of its connections is bound to –
A → B → A, and the AWS VPC CNI hands out the first IP again once its
cooldown has passed – that connection is on the wire as itself again. Its
rules are identities and are installed anyway: they replace the previous
hop's, which would still rewrite the connection to the address of the hop
before. It needs no conntrack placeholder (3.2). Connections bound to the
intermediate address are translated to the returning one as usual; the
same holds for X → Y → Z → Y. A *new* pod that receives a recycled address
is still never touched (3.1): only the harvested 5-tuples are translated.

The second hop is also the first whose source pod was itself restored, and
it keeps that restore's annotations. The agent's shield janitor (which
lowers shields a restore left behind) must therefore never touch the source
of a migration in progress: during the final dump CRIU thaws the cgroup, so
"no container paused" does not tell a leftover from a freeze. Measured on
EKS before that rule: the janitor lowered the second hop's shield during
the 1.3 s dump, the dumped sockets came alive again, and when the source
processes ended their resets reached all players through the first hop's
translation.

Tests: `internal/phantom/chain_test.go` (rule tables of four nodes across
A→B→C, A→B→A with a new address, A→B→A with the first address back, and
X→Y→Z→Y; packets of every connection through them in both directions,
before and after releasing earlier hops, and after the first hop reports
flows ended that later hops took over), `internal/agent/janitor_test.go`.

## 4. Where the programs run (hooks)

| Program | Hook | Serves |
|---|---|---|
| `xl_pod_out` | TCX **egress of the pod's own `eth0`, inside the pod netns** (`KindPod`) | packets leaving a pod (migrated pod and peer pods) |
| `xl_pod_in` | TCX **ingress of the pod's own `eth0`, inside the pod netns** | packets entering a pod; drops inbound packets of *pending* flows |
| `xl_host_out` | TCX egress (head) of node devices that carry pod traffic (`KindHostDevice`) | host-network clients; flows netfilter DNAT'ed to OLD (kube-proxy ClusterIP/NodePort) |
| `xl_host_in` | TCX ingress (head) of the same node devices | replies for those, before conntrack/PREROUTING |
| `xl_host_local` | TCX ingress (head) of the migrated pod's **host-side** veth (`KindHostLocal`) | host-network clients **on the target node** |

All programs are attached with `link.AttachTCX(... Anchor: link.Head())`;
on kernels without TCX they fall back to a clsact qdisc + `cls_bpf`
direct-action filter (priority 1, handle `0x7061`). Both paths are tested.

### 4.1 Pod programs inside the pod netns (decision, with evidence)

The task statement suggested the pod's **host-side** veth as the
translation boundary (ingress = leaving the pod, egress = entering it). For
the direction *leaving* the pod that works (TCX head on `lxc*` ingress runs
before `cil_from_container`). For the direction *entering* the pod it does
not work with Cilium:

* `bpftool net show` on k8s-w-2 (Cilium 1.20.2, TCX attach mode, BPF host
  routing, vxlan, KPR): every `lxc*` device has **only**
  `tcx/ingress cil_from_container`; there is no egress program.
* `tcpdump -Q out` on the host-side veth of a test pod while a client on
  k8s-w-4 and a client on the same node stream to it: **0 packets**
  host→pod, while `-Q in` showed 744 packets pod→host in the same 4 s.
  Cilium delivers into the pod with `bpf_redirect_peer()`, which bypasses
  the host-side veth's transmit path, so a tc/TCX egress program there
  never runs (the AF_PACKET tap sits on the same path).

The pod's own `eth0` ingress hook inside the pod netns sees every packet the
pod receives, whatever the CNI did on the host side (`redirect_peer`
re-runs the ingress hook of the peer device; netkit likewise injects into
the peer). No CNI attaches programs there, so ordering inside the pod netns
is not an issue. The same holds for egress. Therefore the default
placement is **inside the pod netns, both directions**; `KindPodHostSide`
(host-side veth) remains available for CNIs that deliver through the
host-side veth (Calico iptables, AWS VPC CNI, flannel/bridge).

Consequences: the CNI only ever sees NEW — source-IP verification
(`cil_from_container`), ipcache lookups and tunnel selection, network
policy, and NodePort/egress NAT all work on NEW as for any new pod. The
agent needs the pod netns path (it has `hostPID`; CRI reports the sandbox
netns) and attaches from a thread that entered the netns. A TCX link dies
with the interface; `PruneDefunct` removes stale pins.

### 4.2 Host network namespace (decision)

Host-originated packets have no pod veth. Candidates:

* **cgroup/connect4 (+ sendmsg/getpeername), like Cilium's socket-LB** —
  rejected as the main mechanism: it only affects `connect()` of *new*
  sockets; the established host sockets of a migration are already
  connected to OLD and need per-packet translation.
* **tc on the uplink only** — wrong for overlays: with Cilium tunnel mode
  the host routes pod CIDRs via `cilium_host`, with Calico IPIP via
  `tunl0`, with VXLAN via `vxlan.calico`/`flannel.1`.
* **netfilter (nft DNAT/SNAT)** — would interact with kube-proxy's NAT
  state and conntrack zones; we do not touch the node's rulesets.
* **Chosen: TCX head on the node devices that carry pod traffic** (the
  output devices of the routes for OLD and NEW; for Cilium `cilium_host`,
  `cilium_vxlan`/`cilium_geneve` and the uplink; for Calico the uplink and
  `tunl0`/`vxlan.calico`; for AWS VPC CNI the ENIs). Routes count in
  **every** routing table – policy routing sends a secondary-ENI pod's
  traffic out of its own ENI (`from <pod> lookup <n>`), which the main
  table never names – and the agent's route watcher attaches to devices
  that appear while translations exist (a hot-added ENI). Egress runs after
  routing and after POSTROUTING (conntrack/NAT), ingress before PREROUTING:
  * `xl_host_out` rewrites, then **re-routes**: the routing decision was
    made for OLD. A FIB lookup for NEW (ingress perspective — with
    `BPF_FIB_LOOKUP_OUTPUT` the ifindex is a strict output-interface
    constraint and the lookup falls back to the default route; found in
    testing) yields the right device and next hop; same device → L2 header
    fixed in place and the CNI's program on the device still runs; other
    device → `bpf_redirect_neigh()`. On collect_md overlay devices where the
    CNI chose the tunnel endpoint before us (Cilium redirecting NodePort
    traffic straight into `cilium_vxlan`), `FlagTunnel` rewrites the
    tunnel remote to the NEW node.
  * `xl_host_in` translates replies before conntrack, so kube-proxy's
    conntrack entries (made for OLD) un-NAT them correctly.
* **Host client on the target node itself** (`xl_host_local`): the reply
  leaves the migrated pod with source NEW (pod program) and must reach a
  host socket that expects OLD, without crossing any further hook. After
  translating on the host-side veth ingress, the source is OLD — which
  Cilium's source verification and a strict `rp_filter` on the veth drop.
  So the packet is re-injected with `bpf_redirect(..., BPF_F_INGRESS)` on
  **the device the host routes OLD through** (destination MAC set to that
  device's MAC). Reverse-path filtering then agrees by construction, and the
  host socket's cached input route (early demux) still matches. A first
  version used `lo`; strict rp_filter dropped it
  (`TcpExtIPReversePathFilter` counted the drops).

## 5. What survives: matrix

Legend: **T** tested in the netns model (real TCP streams, migration
simulated by re-wiring the pod's namespace, zero sequence gaps) · **U**
unit/datapath-tested · **D** designed, not yet run on that CNI · **✗** not
preserved → Paguro must choose an IP-preserving adapter or close/fail.

| # | Flow | kube-proxy (iptables/ipvs) clusters: Calico, AWS VPC CNI, flannel | Cilium (KPR, socket-LB, tunnel) |
|---|---|---|---|
| a | pod ↔ migrated pod, peer on another node | T | T (cluster; hooks inside pod netns, Cilium only sees NEW) |
| b | pod ↔ migrated pod, peer on the target node | T | T (cluster, chained migrations) |
| c | host-network client on another node (kubelet, hostNetwork pods, node agents) | T | D (`cilium_host` egress / `cilium_vxlan` ingress) |
| d | host-network client on the target node | T | D (re-inject on `cilium_host`, the route of OLD) |
| e | pod → ClusterIP → migrated pod | T (DNAT on the peer's node; host-scope rules) | by construction = (a): socket-LB connects the socket to the backend IP |
| f | outside → NodePort/LoadBalancer `eTP: Cluster` → migrated pod | T (DNAT+masquerade on the entry node, incl. collision test; Flannel cluster 6/6 chained) | T with the backend keeper (tunnel-remote rewrite; 4/4 and 6/6 chained) — only while Cilium still routes the old address, see 8.2 |
| g | outside → NodePort/LB `eTP: Local` | ✗ (replies would leave through the target node, not the entry node) | ✗ |
| h | in-cluster Ingress controller (pod or hostNetwork) → migrated pod | = a/b/c/d | = a/b/c/d |
| i | migrated pod → pod / node in the cluster | T | D |
| k | migrated pod → ClusterIP (kube-proxy DNAT on the OLD node) | U (old node's conntrack gives the backend; port rewrite) | = i (socket-LB) |
| l | migrated pod → external, masqueraded by the old node | ✗ (T: confirmed broken) | ✗ |
| m | external → pod IP directly (routable pod IPs: AWS VPC CNI, BGP, NLB/ALB IP targets) | ✗ (the external peer cannot be programmed) | ✗ |
| n | peer is itself a migrated pod (chained migrations) | U (planner composes both translations) | U |
| o | connected UDP (incl. QUIC clients) | U (IPv4+IPv6) | U |
| p | UDP servers (unconnected sockets: game servers, QUIC) | T for clients through a Service, also masqueraded with `--random-fully` behind a NodePort/LoadBalancer (every node moves their NAT bindings to NEW with the same masquerade port; the hold keeps the server from writing first, [below](#udp-servers)); ✗ for clients on the pod IP (no per-peer socket to harvest) | ✗ |
| q | IPv6 TCP | U (datapath, sockets test) | U |

### UDP servers

An unconnected UDP socket (game server, QUIC, DNS) has no peer, so there
is nothing to harvest and translate, and the server knows each client by
the address its datagrams come from. Its clients usually come through a
Service; kube-proxy's NAT on the client's node then carries the session to
the new IP – as long as the client keeps that address:

* **Through a ClusterIP** (no masquerade) the server knows the client by
  the client's own address. When the old endpoint stops serving,
  kube-proxy deletes the stale UDP entries to OLD, and the client's next
  datagram is bound to NEW with the same source port.
* **Through a NodePort or LoadBalancer** (`externalTrafficPolicy: Cluster`)
  the client is masqueraded on its entry node, and the server knows it by
  the entry node's address and the port the masquerade chose. A datagram
  NATed afresh keeps that port only if the masquerade keeps it, and
  kube-proxy masquerades with `--random-fully` wherever iptables supports
  it: every new binding gets a random port. *The re-bound flow does not
  keep its source port*, except where the masquerade keeps the client's
  port. Measured on EKS 1.37 without the move of the bindings described
  below (AWS VPC CNI, kube-proxy iptables mode, iptables 1.8.11, Xonotic
  behind an NLB; addresses replaced by documentation ones): the player's
  entry on the entry node was `203.0.113.7:46683 → 10.0.1.20:31716`, reply
  `OLD:26000 → 10.0.1.20:63723`; kube-proxy deleted it at the cutover, and
  43 ms later the player's next datagram created one with reply
  `NEW:26000 → 10.0.1.20:34700`. The restored server saw a stranger and
  never answered it, and both ends timed out after 30 s. A ClusterIP player
  on the same node kept its port and its session. OpenArena (ioquake3,
  8 migrations, the same entry node, also without the move): in 6 the NLB players' datagrams
  reached the new pod with a new masquerade port (ioquake3 tolerates that:
  "SV_PacketEvent: fixing up a translated port", its qport), in 2 they
  reached it only at a kube-proxy sync 8.5 s after the restore – the
  ClusterIP player's only after 9.6 s. Waiting for kube-proxy costs both
  the port and the time.

**Moving the bindings.** Paguro therefore does not leave the binding to a
fresh NAT. During the freeze the source lists the ports of the pod's
unconnected UDP sockets (`phantom.UDPServerPorts`: bound to a wildcard or the
old address, not to loopback) and publishes them with the commit
(`status.source.phantom.udpServerPorts`). Every agent then records its node's
conntrack entries of those servers' clients – UDP, the reply from OLD on
one of the ports, translated by a Service (DNAT from another address), a
stream rather than a one-shot query, and not a connection Phantom mode
translates itself (a connected socket's harvested flow). As soon as the
target reports the new IP (`status.target.phantom.programmedAt`, before the
restore), the node replaces each of them with the same binding to NEW –
itself, without waiting for kube-proxy's sync or the EndpointSlices, and
also when kube-proxy re-bound a client with a new port first
(`internal/ctguard/rebind.go`, `internal/agent/udprebind.go`):

```
before:  orig client:p → entry:nodePort   reply OLD:26000 → entry:63723
after:   orig client:p → entry:nodePort   reply NEW:26000 → entry:63723
```

The entry is created through ctnetlink like a guarded entry of the keep-IP
NAT guard: the untranslated reply tuple plus NAT ranges pinned to exactly
NEW:26000 (DNAT) and entry:63723 (SNAT, pinned even without masquerade), so
that the kernel sets up a real NAT binding (`IPS_DST_NAT`, `IPS_SRC_NAT`
and their DONE bits) rather than two tuples that never rewrite a packet.
The client's datagrams then go to NEW from the port the server knows,
without passing kube-proxy's rules again, and the server's replies are
de-NATed on the entry node as before. kube-proxy's clean-up leaves the
moved entries alone: it deletes UDP entries whose reply source is no
serving endpoint of the Service, and NEW is one – the endpoint bridge lists
it as ready before the old endpoint leaves. The entries to OLD it looks for
are gone by then.

Until 30 s after the restore every node keeps the moved bindings in place,
reacting to conntrack events and polling the table (every 250 ms, every
second from 5 s after the restore; only nodes where such clients enter
keep polling, the others stop after one dump at the commit): a moved binding that
something deletes (a kube-proxy clean-up that ran before it counted NEW as
serving) is re-installed, one that a client's datagram got NATed afresh in
between is replaced, and an entry the restored server's own datagram opened
on a binding's reply tuple meanwhile is removed – it would make the
re-install fail and give the client's next datagram a random port again.
While a binding is missing, the client and the server keep re-creating
those two obstacles (one datagram every 33 and 50 ms in the model), so a
re-install that fails asks the kernel which entries hold the binding's two
tuples, removes exactly those (by their conntrack id) and tries again – on
one netlink socket for the whole repair: opening a socket cost 10 ms in the
model (WSL2, kernel 6.6), a request 7 µs, and a repair that opened one per
request lost the race (sessions survived, but up to 65 datagrams per player
arrived from other ports). Nothing has to be undone: before the commit nothing is touched (a rollback
finds the old bindings as they were), and a moved binding is an ordinary
NAT entry to the serving endpoint that ends with its flow. A rollback after
the commit (the frozen phase allows one, e.g. when a warm target never
appears) starts no move, and stops a guard that runs: the source serves at
the old address again. The guard ends after three minutes at the latest,
also when the migration cannot be read. A later
migration of the same pod takes the bindings over on each node. An agent
that sees the migration for the first time only after it succeeded – it
restarted meanwhile, or its events coalesced – still starts the move if the
restore was less than 30 s ago; entries kube-proxy has removed by then are
simply not there to move.

**The hold** stays. The restore wrapper installs it in the new pod's
network namespace before the restore (`shield.HoldUDPReplies`): for 30 s,
datagrams from the ports of unconnected UDP sockets (read from the
checkpoint) pass only when they answer a peer that has written to the pod
since the restore (`ct state new` is dropped; the rule expires by itself
via `meta time`). It keeps the restored server from writing first to a
client whose binding has not moved yet (or, without the move, has not been
re-bound by kube-proxy yet): that datagram (NEW:port → client's address)
matches no binding on the client's node and opens an entry of its own,
which occupies the tuple the binding needs, so that nf_nat gives the client
another port (measured with Minecraft Bedrock on Flannel before the hold:
all eight players timed out 9–10 s after a 0.4 s freeze; with it, 0
disconnects, the players' longest gap 3.0 s with a 0.7 s freeze). With the
bindings moved before the restore, a client's first datagram after the
restore comes from the address the server knows and is answered at once:
the gap is the freeze plus one client interval, not the freeze plus
kube-proxy's re-binding (~2–3 s on EKS).

Measured in the namespace model (`testdata/udp-rebind.sh`: an entry node
with DNAT and `MASQUERADE --random-fully`, a UDP server that knows its
players by address, the migration simulated by re-wiring the server's
namespace): without the move the NodePort player is lost – after
kube-proxy's clean-up every datagram reaches the server from a new port,
and the player times out – while the ClusterIP player keeps its session
(longest gap 2.1–2.8 s); with the move both keep it in every run (8 runs:
longest gap 1.1–1.8 s with a 1.1 s freeze, a single datagram from another
port in one run), also when kube-proxy deletes the moved bindings once more
while the server sends, and without the hold when the bindings move only
after the restore (8 runs, at most one datagram from another port). Root tests
against the kernel's table: `internal/ctguard/kernel_test.go`.

Measured on EKS 1.37 with the move (AWS VPC CNI, kube-proxy iptables mode
with `--random-fully`, players behind an NLB through one entry node):
Xonotic 0.8.6 with a real client through the NLB and one through a
ClusterIP, 4 migrations – both kept their sessions, the NLB player's
binding kept its masquerade port through all four, longest gap
0.66–0.73 s with 0.45–0.49 s freezes. Red Eclipse 2.0.9 (ENet, which
discards datagrams from an unexpected address): 5 migrations with two real
clients (longest gap 0.33–0.54 s, freezes 0.29–0.48 s) and 28 more with a
human player on the Steam client through the NLB – no session lost.

Limits:

* Only NAT in netfilter's conntrack zone 0: kube-proxy in iptables or
  nftables mode. IPVS keeps its own connection table, and CNIs that
  translate Services in Open vSwitch (Antrea's proxy, OVN-Kubernetes) keep
  their entries in zones of their own; neither is moved. Cilium's
  kube-proxy replacement is a column of its own (✗ above).
* The bindings are recorded at the commit. A proxy that deleted the stale
  entries before the agents react (one watch event and a conntrack dump)
  leaves those clients to a fresh binding; kube-proxy deletes them only
  when the old endpoint stops serving (2.5 s after the restore on EKS).
* IPv4 and IPv6, for the pod's primary address (`status.sourcePodIP`); the
  second family of a dual-stack pod is not moved.
* A connected UDP server socket (a harvested flow) whose client is
  masqueraded on its entry node is translated, but kube-proxy's clean-up
  still deletes its NAT binding, and the client is re-bound with a new
  port, as before; its binding is not moved, because the entry node's
  translation for that flow expects the old one.
* Clients that write to the pod IP directly keep writing to OLD and are
  lost, as before.

Cases g, l, m (and p for clients on the pod IP) are lost in Phantom mode. With
an IP-preserving adapter, g and m survive; **l does not survive in any mode
without an egress anchor** (the masquerade state lives on the old node),
see [section 8](#8-external-traffic).

## 6. Packet flows

Notation: `[x]` = hook with Paguro program, `→` = packet path.
Example addresses: OLD 10.244.2.10 (old node B), NEW 10.244.3.20 (target
node T), peer pod C 10.244.1.10 on node A, node IPs A/B/T.

### 6a. Peer pod on another node

```
 C (node A)                                              migrated pod (node T)
 socket C:p → OLD:L                                      socket OLD:L ← C:p
   │ [xl_pod_out @C eth0 egress]  dst OLD→NEW              ▲ [xl_pod_in @pod eth0 ingress] dst NEW→OLD
   ▼                                                       │
 C:p → NEW:L ─ lxc/cali (CNI: policy, routing for NEW) ─ tunnel/underlay ─ CNI on T ─┘

 reply: OLD:L → C:p  [xl_pod_out @pod]  src OLD→NEW  →  NEW:L → C:p on the wire
        [xl_pod_in @C]  src NEW→OLD  →  C's socket sees OLD:L
```

### 6b. Peer pod on the target node

Same as 6a; the packet goes `C eth0 → C's host veth → (CNI local delivery)
→ pod eth0`. Both pods' hooks are inside their own netns, so the CNI's
local fast path (`bpf_redirect_peer`) does not matter. (e2e c4)

### 6c. Host-network client on another node

```
 node A host socket A:p → OLD:L
   routing for OLD → output device D (uplink / cilium_host / tunl0 ...)
   [xl_host_out @D egress, head]  dst OLD→NEW, FIB(NEW): same device → fix MAC; else redirect_neigh
   → wire A:p → NEW:L → node T → pod [xl_pod_in] dst NEW→OLD
 reply NEW:L → A:p arrives on A's device [xl_host_in @ingress, head] src NEW→OLD → socket
```
(e2e c2: routes for OLD and NEW use different next hops on the same uplink.)

### 6d. Host-network client on the target node

```
 node T host socket T:p → OLD:L
   [xl_host_out @uplink egress]  dst OLD→NEW, FIB(NEW) = pod's host veth → redirect_neigh
   → [xl_pod_in @pod] dst NEW→OLD → socket
 reply OLD:L → T:p  [xl_pod_out @pod] src OLD→NEW
   → [xl_host_local @pod's host veth ingress] src NEW→OLD, redirect into the
     ingress of the device the host routes OLD through (MAC := its MAC)
   → host stack (rp_filter/early demux consistent) → socket
```
(e2e c3, with strict rp_filter on all devices.)

### 6e. Pod → ClusterIP via kube-proxy (DNAT on the peer's node)

```
 C socket → VIP:80   (C's pod programs: no match, the tuple has the VIP)
   PREROUTING DNAT VIP → OLD:L (existing conntrack entry)
   [xl_host_out @D] dst OLD→NEW (+ re-route) → T → [xl_pod_in] → socket
 reply: pod → NEW:L → C:p  arrives at A [xl_host_in] src NEW→OLD
   conntrack un-DNAT OLD:L → VIP:80 → C
```
The node agent decides per flow whether C's socket sees OLD (pod-scope
rules) or a VIP (host-scope rules): `NodeContext.ViaNetfilter`, e.g. from
the node's conntrack table. Installing both is wrong: a host-scope rule
would translate the reply before the CNI delivers it, so the CNI would see
OLD. (e2e c5)

### 6f. Outside → NodePort/LoadBalancer (eTP: Cluster) via kube-proxy

```
 client X:q → A:30080   PREROUTING DNAT → OLD:L, POSTROUTING masquerade → A:p
   [xl_host_out @A egress] A:p → OLD:L ⇒ A:p → NEW:L  (+ re-route)  → T → pod
 reply NEW:L → A:p  [xl_host_in @A ingress] ⇒ OLD:L → A:p
   conntrack: un-SNAT/un-DNAT → A:30080 → X:q
```
The pod's harvested peer is `A:p` (a node IP, so host scope on node A).
Wire-tuple reservation: placeholder conntrack entry `A:p → NEW:L` on A.
(e2e c6 and n6)

With **Cilium KPR** the NodePort DNAT/SNAT happens in `bpf_host` on the
uplink, and the packet is redirected straight into `cilium_vxlan` with the
tunnel key of the OLD node. `xl_host_out` at the head of `cilium_vxlan`
egress rewrites the inner destination and, with `FlagTunnel`, the tunnel
remote to the NEW node; the reply arrives on `cilium_vxlan` ingress, where
`xl_host_in` restores OLD before `cil_from_overlay` does the reverse NAT
from Cilium's own CT/NAT entries (which were created for OLD). This is
designed and unit-tested for the tunnel-key part, **but not yet run on
Cilium** (see open items). In native-routing mode, Cilium's `redirect_neigh`
to the uplink passes our egress program, which re-routes as in 6c.

### 6g. eTP: Local — not preserved

The entry node is the old node (only nodes with a local endpoint receive
traffic). There is no SNAT; the pod answers the client's address directly.
After the migration the reply leaves through the target node, the client
gets it from the wrong address (and the LB stops sending to the old node
when its health check fails). Preserving it needs the reply to be sent
back through the old node — the same anchor mechanism as section 8.

### 6k. Migrated pod → ClusterIP (kube-proxy)

The pod's socket is connected to `VIP:80`; the old node's conntrack holds
the backend B:8080. `ResolveWithConntrack` (run on the old node at freeze)
records `Wire = B:8080`. Target rules: `OLD:q → VIP:80 ⇒ NEW:q → B:8080`
and `B:8080 → NEW:q ⇒ VIP:80 → OLD:q`; on B's node the peer rules see the
pod as OLD (DNAT only). New connections of the pod use the Service as
usual. With Cilium socket-LB the socket is already connected to B.

### 6l. Migrated pod → external (masqueraded) — see section 8.

## 7. Interaction with CNIs, policy and conntrack

**Cilium.** Pod programs run inside the pod netns, before `lxc` ingress
(`cil_from_container`) and after the `redirect_peer` delivery. Cilium sees
NEW only: source verification passes, ipcache resolves NEW → target node
and the pod's identity; OLD is gone from the ipcache and is never needed.
Identity of the migrated pod = identity of its labels (unchanged), so
policies keep applying. Cilium's CT creates new entries for the picked-up
flows (it does not require a SYN). Socket-LB means pod→Service flows are
socket→backend flows (case a). Host scope: see 6c/6f and the open items.

**Calico (iptables and eBPF mode).** Same reasoning; Calico's anti-spoofing
(rp_filter / eBPF source check on `cali*`) only sees NEW. In iptables mode
conntrack picks up mid-stream TCP (`nf_conntrack_tcp_loose=1`, the default;
picked-up connections get `BE_LIBERAL` window tracking) and the policy chain
evaluates the first packet as a new connection between the same two
workloads, which was allowed before. One exception, measured: a ClusterIP
client on the node the pod moves to. kube-proxy's DNAT still points to OLD,
so the reply must leave the new pod's veth translated back to OLD – and
Felix's strict rpfilter on workload traffic (`cali-PREROUTING … rpfilter
--validmark --invert -j DROP`) drops it; the connection was one-way dead for
as long as the pod stayed there. Calico (and Canal, where Felix runs too)
therefore count as source-verifying CNIs (below).

**Open vSwitch CNIs (Antrea; same class: OVN-Kubernetes, Kube-OVN).**
Tested with Antrea 2.7 (Geneve, AntreaProxy). Three things differ from
the other classes, each found by a measurement that failed first:

* *Services are translated inside OVS.* A pod's ClusterIP connection is
  DNAT'ed by OVS and tunnelled to the backend's node directly; it never
  crosses a host interface. The DNAT is visible in the kernel's conntrack
  (OVS uses it, zone 65520), so `ViaNetfilter` classifies the flow as host
  scope, and the host programs also sit on the OVS tunnel ports
  (`genev_sys_6081`, `vxlan_sys_4789`, ...): collect_md devices like
  `cilium_vxlan`, where the inner destination and the tunnel endpoint are
  rewritten.
* *Spoof guard.* A reply that leaves the migrated pod's port with OLD as
  its source is dropped (a local client behind the DNAT on the target
  node: the connection hung). For CNIs that verify source addresses
  (`SourceVerify`: Open vSwitch CNIs, Cilium, Calico, Canal) the planner hands such a
  reply to the host stack instead (`FlagLocal`, `xl_host_local`, as for a
  host client on the target node); the host routes it back through the
  gateway port, which carries any source, and OVS undoes its DNAT.
* *Symmetric paths.* A client pod that reached OLD through its gateway
  (OLD was on another node) and whose peer now runs on its own node sent
  the translated frames to the gateway MAC: they hairpinned through the
  host, OVS marked the connection "from the gateway" and sent the replies
  to the gateway, where they were lost (21 s stalls until the pod moved
  away again). The client's translation now re-resolves the next hop when
  NEW is on its segment (`FlagNeigh`, set by the agent after a route
  lookup in the client's netns): `bpf_redirect_neigh` without parameters
  routes the rewritten packet and replaces its route – with NEW as an
  explicit next hop, the first packet waits for ARP and is then sent
  along its original route, to the gateway (kernel behaviour,
  `__neigh_update`). bpf_fib_lookup is no option inside pods: it requires
  forwarding.

Result: three clients at once – pod IP, ClusterIP, external NodePort –
6/6 migrations alternating between two nodes, 0 losses, max gaps
675/695/742 ms.

**AWS VPC CNI.** NEW is a secondary IP of the target node's ENI, OLD was one
of the old node's; the VPC fabric only ever sees NEW. Security groups for
pods (branch ENIs) are per pod, not per IP. The VPC CNI's IP cooldown
(30 s by default before a released IP is reused) covers the window between
old-pod deletion and peers being programmed.

**NetworkPolicy.** Because the wire carries NEW, policies are evaluated
against the new pod (same labels, same namespace) — as for any new pod.
`ipBlock` rules that name OLD explicitly would not match (rare for pod
IPs). Policy-port semantics are unchanged: translation keeps the service
port; only flows that the old node DNAT'ed have their port rewritten.

**Kernel conntrack** on peers/routers sees the migrated flows as new
mid-stream connections with NEW (loose pickup). On kube-proxy nodes the
existing entries made for OLD stay valid because host-scope translation
happens outside netfilter's view (egress after POSTROUTING, ingress before
PREROUTING).

## 8. External traffic

### 8.1 Migrated pod → external endpoint behind SNAT (case l)

The external peer saw the **old node's** masquerade tuple `B:x`. After the
migration the target node masquerades to `T:y`; the peer resets. This
breaks in *every* Paguro mode with node masquerading — including today's
Cilium sticky-IP mode with `bpf.masquerade=true` — because the NAT state
lives on the old node.

Options:

* **(a) Stable egress IP (recommended configuration).** Cilium Egress
  Gateway / Calico egress gateway / AWS NAT gateway with an Elastic IP per
  workload. With an egress *gateway node*, the NAT state is on the gateway,
  not on the old node. Combined with sticky IPs the flow survives if the
  gateway's NAT entry is keyed by the (unchanged) pod IP. In Phantom mode the
  gateway node needs host-scope rules that translate NEW back to OLD before
  its SNAT (design, untested). AWS NAT gateways key their mapping by the
  pod's source IP, so Phantom mode cannot preserve such flows.
* **(b) Anchor on the old node (design).** Keep the old node in the path
  for these flows: the target pod's outbound packets of an anchored flow
  are tunnelled (collect_md ipip/fou device owned by Paguro) to the old
  node, translated to OLD there and sent through the old node's existing
  NAT entry; the replies are un-NAT'ed to OLD on the old node and sent back
  to NEW (as in 6c). Cost: the old node must stay up and keep the NAT entry
  (Cilium: BPF NAT map, kernel: conntrack), one extra hop and encapsulation
  for those flows, CNI-specific handling of the reply on the old node
  (Cilium's reverse NAT would deliver to a no-longer-existing endpoint).
  Not implemented.
* **(c) Migrate the NAT state.** Inject the conntrack entry (kernel NAT)
  on the target node and make the target node send with the old node's
  address — fails on any network with source anti-spoofing (cloud
  security groups, OpenStack port security), and the replies still go to
  the old node. Rejected.

**Decision:** Phantom mode reports these flows as `Unsupported` at freeze time
(`Plan` → `PlanResult.Unsupported`; `ResolveWithConntrack` +
`Classify` mark them). The controller then applies the pod's policy
(`fail`/`close`, or choose an IP-preserving adapter **with** an egress
gateway). The e2e test shows the flow breaking (c8) on purpose.

### 8.2 Outside clients entering via a cluster node

* `eTP: Cluster`, kube-proxy: preserved (6f, tested).
* `eTP: Cluster`, Cilium KPR: preserved with the backend keeper
  (controller, keeper.go), tested. Cilium's eBPF load balancer decides per
  packet, from its ipcache, whether the old backend address is a cluster
  endpoint (into the tunnel, SNAT to the node's router IP – where our
  rewrite happens) or outside the cluster (SNAT to the node IP, out of the
  uplink). It stays a cluster endpoint while a node's pod CIDR covers it.
  When that ends – a sticky /32 released with the source pod, or the old
  node deleted after a drain – Cilium switches the connection to the world
  path with a new source tuple: the client's packets leave the cluster, and
  the next packet of the restored socket is answered by the entry node's
  kernel with a reset. Measured with a sticky IP: client hung, server
  socket reset within seconds. Hence Phantom mode is refused for pods with a
  sticky IP (Preserve keeps every connection there), and pods meant for
  Phantom mode get no sticky IP (`paguro.dev/network: phantom`). When a
  drained node is deleted, its pod CIDR goes the same way. Such connections
  cannot be kept on Cilium, but they must not hang either: the agents watch
  the routes of old addresses (section 11) and report one that is no longer
  routed into the cluster (`status.phantomUnroutable`, after 5 s, so that a
  restarting CNI agent's route flap does not count). The controller drops it
  from the backend keeper; Cilium then picks the new backend and the client
  gets a reset at once. Measured: reset 5.7 s after the old subnet's route was
  removed on the entry node, the in-cluster connection unaffected; a route
  flap of 1 s changed nothing.
* `eTP: Local`: not preserved (6g).
* Ingress controllers inside the cluster: in-cluster peers (6a–6d).
* Cloud load balancers with IP targets (AWS NLB/ALB `target-type: ip`):
  the LB connects to the pod IP directly → case m, not preserved. With
  instance targets (NodePort) → `eTP` rules above.

## 9. The pod IP changes: what users see

* `pod.status.podIP(s)` and the EndpointSlices show **NEW**. New
  connections through Services, DNS (also headless), and kubelet probes go
  to NEW.
* The restored process still has OLD in memory: environment variables
  from the Downward API (`POD_IP`), self-registrations in service
  discovery (Consul, Eureka), advertised listeners (Kafka
  `advertised.listeners`, Redis Cluster, Cassandra, Elasticsearch,
  etcd/ZooKeeper peer URLs). Anything that hands OLD to *other* parties for
  *future* connections breaks (those connections are new and are not
  translated). Paguro cannot fix that; such workloads must use an
  IP-preserving adapter or stable DNS names. The controller should refuse
  Phantom mode for pods annotated `paguro.dev/advertises-pod-ip: "true"` and
  for StatefulSets of known peer-to-peer systems unless explicitly forced.
* Listeners the app bound to **OLD specifically** (`server.address=$POD_IP`)
  are restored as `OLD:port`; new connections to `NEW:port` (and kubelet
  probes!) would get RST. Paguro installs a small nftables table in the pod
  netns (`InstallSelfIPFixup`, same mechanism as the RST shield) that
  DNATs **connection-opening SYNs** for `NEW:port → OLD:port` on exactly
  those ports (`HarvestOldBoundListeners`), and SNATs new outbound SYNs
  sent from OLD to NEW. Restored flows are never touched (they are not
  SYNs and `xl_pod_in` already translated them before netfilter).
* `kubectl exec` and new processes see NEW on `eth0` and OLD on `lo`; the
  pod also gets `arp_announce=2` (below). The pod's annotation
  `paguro.dev/old-ip: <OLD>` documents the translation for operators.
* Logs/metrics labelled with the pod IP change; NetworkPolicies are
  unaffected (label-based).

### New connections during the migration

Connections opened while the pod moves are not among the harvested flows;
three things keep them from failing:

* **Endpoint bridge** (controller, `bridge.go`), as with a kept IP: from the
  freeze until the replacement has been ready for 10 s, every Service of the
  pod has a slice of Paguro's that lists NEW as ready. Without it a Service
  had no endpoint at all once the frozen source failed its readiness probe
  (proxies fall back to a terminating endpoint only while it is serving)
  and the replacement had not passed its own yet – measured on EKS with a
  30 s initial delay: every new connection refused for 19 s. kube-proxy
  resolves the same address in two slices at random when neither is
  terminating, so while the replacement's own slice lists NEW as not ready
  the bridge wins only some of its syncs; hence:
* **Probes without the cold-start delay** (webhook): the replacement's
  readiness probe has no initial delay – it continues processes that were
  serving; a startup probe's delay moves into its failure budget, so a cold
  start after a failed restore has as long as before. Liveness probes stay.
  The trade-off: after a failed restore the cold-started replacement is
  probed at once too, so an application whose readiness endpoint answers
  before it has warmed up gets traffic earlier than its delay intended.
* **Attempts that went to OLD are handed back** (every agent, `phantomsyn.go`):
  a connect() during the freeze is DNAT'ed to OLD, its SYN dropped behind
  the shield, and its retransmissions stay with OLD (conntrack fixed the
  backend) – measured: such a connection hung for the client's 12 s
  timeout although the replacement served 1.5 s later. From the restore
  until 10 s after the migration succeeded, the agents delete the conntrack
  entries of TCP attempts that a NAT sent to OLD and that got no answer for
  a second; the next retransmission is load-balanced again. Attempts
  addressed to OLD itself are left alone (they would go there again).
  Tested in a namespace model (`TestUnansweredSYNHandedBack`, with the
  negative control).

## 10. Lifetime and garbage collection

* Every rule carries its migration id (`Rule.Owner`) and per-rule counters
  (`packets`, `last_seen`), visible via `Translator.Rules()`.
* **Authoritative GC:** the target agent periodically (e.g. every 10 s)
  calls `LiveFlows(podNetns, OLD, flows)` — a `sock_diag` dump of the
  restored pod. A flow whose socket no longer exists (any state, including
  TIME_WAIT, counts as alive) is dead on every node. The controller removes
  dead flows from the published list; every agent recomputes `Plan` for
  the removed flows and calls `Translator.RevertOwned` (rules **and**
  reservations; a rule a later migration of the pod took over stays, 3.3).
  When the pod is deleted, all its flows are dead.
* Backstop: an agent whose Migration object is gone deletes the owner's
  rules (`DeleteOwner`). `last_seen` allows an operator-defined idle limit,
  but it is *not* used automatically: idle long-lived connections (DB pools
  without keepalive) must not be cut.
* Because translation is per flow, OLD can be reused by IPAM at any time
  without affecting the new owner (see 3.1; the routes that steer the
  translated flows select them by their exact tuple too, section 11) – or come back to the pod
  itself on a later hop (3.3). Remaining window: between the
  old pod's deletion (CNI DEL) and the peers being programmed, a peer's
  retransmission to OLD could reach a *new* owner of OLD and be answered
  with RST. Mitigations: AWS VPC CNI cooldown (30 s); for other IPAMs the
  controller programs peers right after the target sandbox exists, i.e.
  long before the IP is likely to be reused; residual risk documented.

## 11. Robustness and failure safety

* **Pass-through by default:** only exact table hits are modified; non-IP,
  non-TCP/UDP, fragments, ICMP, IPv6 with extension headers are always
  passed (`non-candidates-pass` test). Programs return `TCX_NEXT`, so the
  CNI's programs that follow always run.
* **The only drop:** inbound packets of a flow flagged *pending* (restore
  not finished) — a deliberate "freeze" for that one flow. Clearing the
  flag is a single map update.
* **Routes of old addresses:** where a node translates after routing (host
  scope, peer pods), the translated connections to the old address must
  still leave towards the cluster. Paguro routes them like the new address
  when the CNI does not route the old one through a gateway – on-link on
  the old bridge (Flannel) or in the VPC subnet (AWS VPC CNI, where an
  address nobody has gets no ARP answer), a blackhole for the old block
  (Calico), or only the host's default route because the old node's pod
  subnet route is gone (node deleted after a drain). The route lives in a
  table of its own (4242, own protocol number), and **only the translated
  flows select it, by their exact tuple** (source, destination, ports,
  protocol – the tuple the kernel routes by, after DNAT and before SNAT,
  from conntrack). So only the migrated connections take it; any other
  connection to the old address – a pod that received it (3.1) – follows
  the CNI's routes, also while migrated connections live. (The first
  version put the /32 into the main table, where it beat the CNI's subnet
  route by prefix length. Measured on EKS: after the VPC CNI's cooldown the
  old address went to another pod, and the peer node sent every new
  connection to it to the migrated pod's node, where it was lost.)
  The kernel walks its policy rules one by one for every route lookup, and
  a node does a lookup for every packet it forwards – for all its pods. So
  the number of rules a forwarded packet passes does not grow with the
  migrated connections (a database with a few thousand pooled connections
  from one node's pods would otherwise cost each packet of that node
  thousands of rule matches, for as long as the connections live):
  * **Forwarded connections** (host scope: pods behind a ClusterIP,
    NodePort clients on their entry node) are steered by a bit of the
    packet mark. Their tuples are elements of an nftables set (table
    `inet paguro_phantom_steer` in the host namespace); a prerouting chain
    after the DNAT sets the bit on their packets – a hash lookup – and one
    rule per family (priority 81, `fwmark 0x2000/0x2000 lookup 4242`)
    selects the table. A forward chain clears the bit right after routing,
    so the CNI's programs, tunnels and other rules never see it. The bit is
    `phantom.steeringMark` (agent flag `--phantom-steering-mark`), by
    default `0x2000`: outside kube-proxy's `0x4000`/`0x8000`, Cilium's
    `0x0F00`/`0x1E00` values and identity bits, Calico's default mask
    `0xffff0000` and the AWS VPC CNI's `0x80`.
  * **Connections of local sockets** – host sockets, and the flows in a
    peer pod's namespace – keep one rule per flow (priority 80): their route
    is looked up by the socket itself, before any netfilter hook (on
    Calico's old node, the blackhole of the old block refuses that lookup,
    and the packet would never reach a chain that marks it). In the host
    namespace a gate (priority 79, `not iif lo goto 81`) lets everything but
    the host's own route lookups jump over these rules; in a pod they cost
    only that pod.
  * Without a usable `nft` on the node, forwarded connections fall back to a
    rule each (and a warning in the agent's log).

  Steering follows the live flows (`syncSteering`: after programming, ended
  flows, releases and every route check); the kernel dissects the ports of
  the packets it routes while a per-flow rule exists (Linux ≥ 4.17). A
  flow's routing tuple is read from conntrack once (its NAT mapping does not
  change while it lives). When conntrack cannot be read, the host's steering
  is only added to, never replaced: the tuples of DNAT'ed and masqueraded
  flows would otherwise give way to ones the kernel does not route by.
  Tested in namespace models: `TestSteeringLeavesARecycledOldAddressAlone`
  (a host socket), `TestSteeringManyForwardedFlows` (200 forwarded
  connections through one mark rule, the recycled address reached by new
  connections, the fallback without nftables) and `TestSteerGate` (both
  families). The agent rechecks the routes whenever the host's routes change (rtnetlink
  notification) and every 30 s; for an address that several chained
  migrations need, the newest one decides. When the CNI's route comes
  back, Paguro's route goes again. An address that
  was routed into the cluster when it was programmed and is not any more
  for 60 s (checked every 10 s, so that a restarting CNI agent or a BGP
  session reset does not count) is reported (`status.phantomUnroutable`);
  the controller then drops
  it from the backend keeper (8.2).
* **Kill switch:** `Translator.SetEnabled(false)` (pinned control map)
  turns every program into a pass-through instantly, without detaching.
* **Verifier-bounded:** no loops over packet data, no tail calls, bounded
  helpers. Helper failures pass the packet unmodified and count `Errors`.
* **Restarts and upgrades:** maps (`/sys/fs/bpf/paguro/phantom/maps`) and
  TCX links (`.../links`) are pinned. A restarted agent re-opens the maps
  and atomically switches every pinned link to the newly loaded programs
  (`link.Update`), keeping its position in the chain (tested:
  `TestAttachLifecycle`, same link ids after a second `New`).
* **Interfaces vanish** (pod deleted): the TCX link becomes defunct;
  `PruneDefunct` removes the pin (tested).
* **Uninstall:** `phantom.Cleanup` detaches all pinned links and legacy
  filters and removes the pins; the agent also releases host-level
  reservations (ports, conntrack placeholders) it recorded.
* **Lazy attachment:** programs are only attached to pods and devices that
  take part in a migrated flow, so unrelated nodes and pods carry zero
  overhead and zero risk.
* Host-device programs touch only host-scope hits; a bug cannot black-hole
  a node's traffic as a whole, and the kill switch disables them.

### MTU, GSO/GRO, checksums

* No encapsulation, packet size unchanged — no MTU impact.
* Addresses/ports are rewritten with `bpf_l3_csum_replace` and
  `bpf_l4_csum_replace(... BPF_F_PSEUDO_HDR)`; this is correct for
  `CHECKSUM_PARTIAL` (local senders, GSO super-packets; the pseudo-header
  sum is adjusted, the NIC/segmentation completes it), `CHECKSUM_COMPLETE`
  (`skb->csum` adjusted) and `CHECKSUM_NONE`. IPv6 uses `bpf_csum_diff`
  over the 16-byte addresses. UDP checksum 0 stays 0
  (`BPF_F_MARK_MANGLED_0`). TCP options are never parsed or touched.
* Evidence: `TestDatapathRewriteAndChecksums` (exact rewrite + Go-side
  checksum verification for TCP/UDP, IPv4/IPv6, zero UDP checksum); e2e
  with TX offload off: `tcpdump -vv` 0 incorrect checksums of 376 694
  packets, `TcpInCsumErrors` 0; 4 MiB bulk transfers (GSO/GRO on veth) in
  `TestTranslationSockets`.

### Pod-side prerequisites (agent, target pod)

* OLD as `/32` (`/128`) on `lo` — the restored sockets bind to it.
* `net.ipv4.conf.{all,default}.arp_announce=2`. **Found in testing:** the
  restored sockets send from OLD, so without it the pod's ARP request for
  its gateway reads "who-has gw tell OLD", which proxy ARP with strict
  rp_filter (Calico-style) refuses to answer; every flow stalled until an
  unrelated packet from NEW refreshed the neighbour entry.
* Self-IP fix-up table (section 9).

### Limits

IPv4/IPv6 TCP and connected UDP; no SCTP; no IP fragments; no IPv6
extension headers; host-scope re-routing after a destination rewrite
(`FlagReroute`/`FlagTunnel`, `xl_host_local` re-injection) is IPv4 only —
IPv6 host-network flows are rewritten but follow the route chosen for OLD
(fine when OLD and NEW leave through the same device and next hop, e.g.
`cilium_host`); ICMP errors (e.g. PMTU "fragmentation needed") are not
translated — in-cluster MTUs are uniform, so this matters only for paths
to the outside, which Phantom mode does not preserve anyway.

**Kernel:** TCX needs 6.6 (Ubuntu 24.04: 6.8 ✓). Fallback clsact/cls_bpf
direct-action works on older kernels; `bpf_redirect_neigh` with next-hop
needs 5.13; no BTF/CO-RE needed (no kernel struct access). bpffs mounted at
`/sys/fs/bpf`. The agent needs CAP_BPF, CAP_NET_ADMIN, CAP_SYS_ADMIN (setns)
— it is already privileged.

## 12. Measurements

All on the development machine (WSL2, kernel 6.6.87, 12 vCPUs), so absolute
numbers are only indicative; the relative numbers are what matters.

**Connection survival (e2e, `testdata/e2e.sh -mode replumb`).** Eight
long-lived symmetric streams (8-byte sequence numbers every 2 ms in both
directions) covering cases a–f, i and l of the matrix. The server is
frozen (SIGSTOP), its namespace is cut from the old node and re-wired to the
target node (eth0 = NEW, OLD on lo), the target node and then the peer nodes
are programmed, the server resumes. Run with TCX and with legacy tc, TX
checksum offload on and off:

* c1–c7 survive with **0 sequence gaps, 0 errors** and keep streaming;
  the maximum gap (1.8–2.9 s) is the simulated freeze (≈1.2 s, includes
  re-wiring and ethtool) plus TCP retransmission backoff. c8 (external via
  old-node SNAT) breaks, as designed.
* After the migration: a new connection from the same peer pod to NEW (n1)
  and a new NodePort connection from another outside client with the same
  source port (n6) both work next to the migrated flows (reservation); a
  new connection to NEW:7006, where the app's listener is bound to OLD, works
  (n7, self-IP fix-up).
* IP reuse: a new pod on the old node gets OLD; a new connection to OLD
  reaches it untouched while the migrated flow to the same OLD:port keeps
  being translated to NEW.
* Removal: rules removed, all links/filters detached twice (idempotent):
  `programs still attached anywhere: 0`; the connection to the recycled OLD
  keeps working.
* Checksums with TX offload off: `tcpdump -vv` **0 incorrect of 376 694**
  packets (wire, new pod, peer); `TcpInCsumErrors` 0.
* Negative controls: `-no-reservations` → n1 and n6 never complete;
  programming peers before the target → the new pod's kernel answers with
  RST (all cross-node flows reset; this is why the target goes first).

**Per-packet cost** (`TestMeasureProgramCost`, `BPF_PROG_TEST_RUN`, 2·10⁶
runs, 100 000 rules installed; the test harness itself costs ≈43 ns, see
"kill switch off"):

| packet | ns/packet incl. harness | ≈ program cost |
|---|---|---|
| non-IP (ARP) | 43 | ~0 |
| IPv4 TCP, no rule | 68 | ~25 |
| IPv4 TCP, translated | 173 | ~130 |

(The first version used `bpf_skb_load_bytes` and counted every packet:
116/211 ns. Direct packet access and counting only hits cut the miss path
by ~60 % of the program cost.)

### 12.1 Throughput and latency

`testdata/bench.sh`: peer → router → pod over veth, programs on both pods'
interfaces, 202 412 rules installed, iperf3 single TCP stream (3 s) and
netperf TCP_RR with 1-byte messages (3 s), CPU-pinned, median of 7
interleaved rounds:

| scenario | throughput | TCP_RR | per round trip |
|---|---|---|---|
| baseline (no programs) | 36.48 Gbit/s | 15 004 /s | 66.65 µs |
| attached, traffic not translated | 35.39 Gbit/s (−3.0 %) | 14 738 /s | 67.85 µs (+1.2 µs) |
| translated (both ends) | 33.00 Gbit/s (−9.5 %) | 14 418 /s | 69.36 µs (+2.7 µs) |

A single TCP stream over veth at 36 Gbit/s is bound by one CPU core, which
is the worst case for any per-packet cost; a round trip passes four
programs (peer egress, pod ingress, pod egress, peer ingress). Unrelated
pods carry no cost at all, because programs are attached lazily only to
endpoints of migrated flows.

### 12.2 Control-plane latency and freeze contribution

`TestMeasureControlPlane` (target node):

| flows | Plan | Apply (attach + reservations + rules) | clear pending |
|---|---|---|---|
| 10 | 27 µs | 0.9 ms | 77 µs |
| 100 | 95 µs | 10 ms | 0.37 ms |
| 1 000 | 0.96 ms | 11.5 ms | 2.5 ms |
| 10 000 | 9.5 ms | 35.6 ms | 28.8 ms |

First attach of a pod (two TCX links created from inside its netns, pinned):
46 ms; repeated attach (idempotent): 0.8 ms.

Freeze contribution: only "clear pending" is on the critical path after the
restore (≤ 3 ms up to 1 000 flows). Harvest (one `sock_diag` dump), target
programming (at sandbox creation) and peer programming (during the CRIU
restore) overlap with work the migration does anyway. The end-to-end
client gap is then dominated by the CRIU freeze and TCP's retransmission
backoff, as in the sticky-IP mode (baseline: freeze 1.1–2.1 s, max client
gap 3.2 s). Not measured with real CRIU in this work package (open item 5).

## 13. Integration (implemented)

The design below is implemented in `internal/agent/phantom*.go`,
`internal/agent/source.go`, `internal/controller/phantom.go` and the wrapper;
differences from the first design are marked.

| Step | Who | What |
|---|---|---|
| preflight | controller | `spec.network: Phantom`, or `Auto` when the CNI cannot keep the IP and every node reports `paguro.dev/phantom: available`. Computes the cluster's prefixes once (`status.network.phantomClusterCIDRs`: node podCIDRs and addresses, ServiceCIDR objects, Cilium/Calico pools, Helm `phantom.clusterCIDRs`). |
| pre-copy converged | source agent → controller | `readyToFreezeAt`; only now is the replacement created (with a new IP its containers would otherwise wait in the wrapper for the whole pre-copy). The source keeps copying (a round per second) until the target reports `sandboxReadyAt`. |
| freeze | source agent | In parallel with the final dump: every address the pod's sockets are bound to (`BoundAddrs`; after chained migrations there can be several), the flows of each (`HarvestFlows`, both socket families: dual-stack servers hold IPv4 clients on v4-mapped IPv6 sockets), conntrack resolution in the old node's namespace, classification, listeners bound to the old IP, the ports of unconnected UDP sockets (`UDPServerPorts`). |
| commit | source agent | **Flows are published only now** (`status.source.phantom`, in the same patch as phase Frozen). Before the commit a rollback can still thaw the source; peers programmed earlier would break its connections. The bound addresses go into the checkpoint metadata. |
| target | target agent | On the commit: new IP and pod netns from the wrapper's sandbox marker, `Plan` per flow (each with its own old IP), `Apply` with inbound rules **pending**, self-IP fix-up; then `status.target.phantom.programmedAt`. |
| peers | every other agent | Only after `programmedAt`: node context (local peer pods via the node-scoped pod cache, host addresses, devices from route lookups plus overlay devices, kube-proxy DNAT from conntrack, tunnel rewrite, other active migrations), `Plan`/`Apply`, `status.phantomNodes[node]`. |
| UDP servers | every agent | On the commit (`udpServerPorts`): its conntrack entries of those servers' clients through a Service; after `programmedAt`: the same bindings to the new IP, kept in place until 30 s after the restore ([UDP servers](#udp-servers)). |
| restore | wrapper | All bound addresses on `lo`, `arp_announce=2`, `--tcp-established`. |
| restored | target agent | Called directly by the restore watcher (no watch round trip): clear the pending flags, abort the flows that cannot be kept (`SOCK_DESTROY`, both families). |
| lifetime | target agent | Every 10 s `LiveFlows`; ended flows → `status.target.phantom.deadFlows`; all ended or the pod gone → `releasedAt`. |
| cold start | every agent | A container cold-started after a failed restore has none of the migrated sockets: the target reports their flows dead at once, and every node aborts its own ends first (`SOCK_DESTROY`: a peer pod's socket, a host socket, a pod's socket to the ClusterIP – its own tuple from conntrack), so that clients waiting for data fail at once instead of after their timeout (measured on EKS before: a clone hung 7 min). Clients outside the cluster (through a NodePort) have no socket on a node and wait for their own timeout. Every node removes exactly what it installed: one state file per migration in `/var/lib/paguro/phantom` (per-flow plans), rules by owner id, reservations reference-counted across migrations (a chained migration reserves the same tuples). With no migration left a node detaches everything and removes its maps. |
| agent restart | every agent | Translator re-opens the pinned maps, `PruneDefunct`, state files re-loaded; a sweep releases migrations that no longer exist. Stale events cannot re-program a released migration (tombstones; the object is re-read under the lock). |

## 14. Open items and risks

1. **Host scope on Cilium after the old node is gone (cases c, f)** –
   NodePort through Cilium's eBPF load balancer works with the backend
   keeper while the old address is still a cluster endpoint for Cilium
   (8.2). After the old node is deleted such connections are reset within
   seconds instead of hanging (tested with the route removal that a node
   deletion causes; a real node deletion is not tested). Keeping them would
   need Cilium to route the old address to the new node. With
   kernel-routing CNIs (Flannel, Calico) the agents' fallback routes keep
   these connections (section 11). Host-network clients on Cilium are not
   measured yet.
2. **Cilium host firewall** (if enabled) would see the old address on
   host-scope replies.
3. **netkit** datapath (Cilium option): TCX on the pod-side netkit device is
   not verified.
4. **External peers** that see the pod IP (routable pod IPs, NLB/ALB IP
   targets) cannot be kept; they are aborted after the restore. Choosing
   the IP-keeping mode per migration when such a flow exists is the next
   step.
5. IPv6/dual-stack pods: datapath tested, cluster not tested.
6. Pod advertising its own IP – undetectable in general (section 9).

Resolved since the first version: real CRIU checkpoint/restore (e2e PASS
for TCX, legacy tc and offload off), dual-stack sockets, chained
migrations, integration into agent and controller.

## 15. Files and tests

```
internal/phantom/
  bpf/phantom.c               eBPF programs (one object, two variants: L2 / L3 devices)
  phantom_bpfel.go/.o         bpf2go output (committed; `go generate` needs clang)
  phantom.go                  Translator: pinned maps, kill switch, stats, Cleanup
  attach.go                   TCX (head) / legacy clsact attach, netns entry, pins, prune
  rules.go                    Rule/Tuple encoding, Upsert/Delete/SetFlags/Rules/DeleteOwner
  plan.go                     Migration/Flow/NodeContext → rules, attachments, reservations
  harvest.go                  sock_diag harvest, conntrack resolution, Classify, LiveFlows
  reserve.go                  ip_local_reserved_ports, conntrack placeholders
  route.go, steer.go          routes of old addresses (table 4242) and the steering that selects them (mark, per-flow rules)
  selfip.go                   nftables self-IP fix-up in the pod netns
  synflush.go                 connection attempts to the old address handed back to the Service
  udpservers.go               ports of a pod's unconnected UDP sockets (sock_diag)
  plan_test.go                planner unit tests (no root)
  chain_test.go               chained migrations through four nodes' rule tables (no root)
  datapath_test.go            root tests: checksums, attach lifecycle, sockets v4/v6, reservation, cost
  testdata/topology.sh        3-node namespace model
  testdata/e2e.sh             migration end-to-end test (replumb | criu, TCX | legacy, offload on|off)
  testdata/bench.sh           throughput/latency overhead
  testdata/flowcheck.py       long-lived sequence-number streams
  testdata/udp-rebind.sh      UDP server behind DNAT + MASQUERADE --random-fully (own namespace model)
  testdata/udpgame.py         UDP game server and player, players known by address
hack/phantom-test/            CLI: attach/detach/plan/harvest/rules/stats/cleanup
internal/ctguard/rebind.go    UDP servers: their clients' NAT bindings moved to the new IP (+ rebind_test.go;
                              kernel_test.go: root, against the kernel's table in a scratch netns)
internal/agent/udprebind.go   when every node moves and guards them (+ udprebind_test.go)
internal/agent/phantomsyn.go  when every node hands such attempts back (+ phantomsyn_test.go)
hack/udprebind-test/          CLI: the move as an agent does it, in the namespace it runs in
```

Run:

```
go test ./internal/phantom/                                    # unit, no root
go test -c -o /tmp/t ./internal/phantom && sudo /tmp/t -test.v # root: datapath, sockets, attach, cost
go build -o bin/paguro-phantom-test ./hack/phantom-test
sudo PHANTOM_TEST=bin/paguro-phantom-test internal/phantom/testdata/e2e.sh -mode replumb [-legacy] [-offload off] [-no-reservations]
sudo PHANTOM_TEST=bin/paguro-phantom-test internal/phantom/testdata/e2e.sh -mode criu   # on a host where CRIU can run
sudo PHANTOM_TEST=bin/paguro-phantom-test internal/phantom/testdata/bench.sh
go test -c -o /tmp/ct ./internal/ctguard && sudo /tmp/ct -test.run Kernel -test.v       # root: moved bindings in the kernel
go build -o bin/paguro-udprebind-test ./hack/udprebind-test
sudo UDPREBIND=bin/paguro-udprebind-test internal/phantom/testdata/udp-rebind.sh [-no-rebind] [-no-hold]   # UDP servers, ~25 s
make bpf-generate                                              # after changing bpf/phantom.c: bpf2go with clang in a container
BPF2GO_CC=clang-19 go generate ./internal/phantom/             # the same with a local clang and llvm-strip (default: clang)
```
