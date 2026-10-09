# Paguro and CNIs

Paguro needs one thing from the network: the migrated pod's connections
must keep working although the pod now runs on another node. There are two
ways to get there:

* **keep the IP** – the CNI can hand the pod's IP to another node (Calico
  with calico-ipam, Cilium with multi-pool IPAM). Every connection survives,
  including peers outside the cluster that talk to the pod IP directly.
  The CNI's hand-over sits inside the freeze.
* **Phantom mode** – the pod gets a new IP; eBPF programs translate the old
  address of each migrated in-cluster connection on the nodes involved
  ([PHANTOM-MODE.md](PHANTOM-MODE.md)). Works with any CNI. The CNI's work happens
  *before* the freeze (the target sandbox is up before the source freezes),
  which makes it the fastest mode measured.

`spec.network: Auto` keeps the IP when the CNI can, otherwise uses Phantom mode
when every node supports it (agent annotation `paguro.dev/phantom: available`),
otherwise falls back to Generic (new IP; the pod's connections are aborted
so that it can reconnect at once).

## How the CNI is detected

Every agent reads its node's **active CNI configuration** – the first file
in `/etc/cni/net.d`, as libcni does – and publishes it as the node annotation
`paguro.dev/cni` (`<name>;<plugin>/<ipam>`). The controller trusts an
IP-preserving adapter only if **both** the source and the target node run a
CNI that can move an IP. CRD-based detection alone is not enough: Calico's
CRDs also exist with Canal, where IPs come from host-local IPAM and are
bound to the node.

## Support matrix (the five most used CNIs, plus others)

| CNI | Typical platform | Detected as | Mode | In-cluster TCP | Peers outside the cluster | Lab status |
|---|---|---|---|---|---|---|
| **Calico** (calico-ipam) | on-prem, many managed | `calico` | keep IP (`ipAddrs`) or Phantom | ✓ | ✓ (keep IP) / closed (Phantom) | Helm-only install (fresh nodes prepared by the node installer); keep IP with commit gate, route guard and cluster-wide NAT guard: UDP game server 4/4 and TCP 0 failed connections via pod IP, ClusterIP and NodePort on a third node (2026-10-04), keep-IP freeze 1.23–1.58 s (floor: Calico's own CNI DEL/ADD); Phantom freeze 0.36–0.90 s |
| **Cilium** (multi-pool) | on-prem, GKE DPv2, AKS (Cilium) | `cilium` | keep IP (sticky /32) or Phantom (pods annotated `paguro.dev/network: phantom`, no sticky IP) | ✓ | ✓ with Egress Gateway (keep IP) | keep IP: 30+ runs; external NodePort client through an uninvolved node kept across an 11.5 s RWO volume move and two short moves (gaps 1.6 s, 2026-10-03); Phantom: 6/6 chained with an in-cluster client and an external client through a NodePort (eBPF LB), freeze 365–467 ms, max gaps 626/752 ms, 0 lost |
| **Flannel** | k3s default, kubeadm | `flannel` | Phantom (chosen by `Auto`) | ✓ | closed (masqueraded flows) | 10/10, freeze 334–466 ms (first 857 ms), max client gap 1.48 s, 0 lost; Paguro installed by `helm install` alone in 10 s |
| **AWS VPC CNI** | EKS default | `aws-vpc-cni` | Phantom | ✓ | closed; NLB/ALB *IP targets* see the new IP only after re-registration | EKS 1.37, AL2023, m7i-flex.large (2026-10-07): Minecraft Java 610/655 ms, Bedrock 443/466 ms, 8 players each, 0 disconnects; pod IPs lie in the node subnets, which the agents publish (`paguro.dev/node-subnets`) |
| **Azure CNI** | AKS default | `azure-cni` | Phantom | ✓ | closed | not runnable in this lab (needs Azure) |
| Canal (Calico + Flannel) | RKE2 default | `canal` | Phantom | ✓ | closed | parser + decision tested |
| **Antrea** | VMware/Tanzu, on-prem | `antrea` | Phantom | ✓ (incl. ClusterIP through Antrea's proxy in Open vSwitch) | closed | 6/6 alternating between two nodes, three clients at once – pod IP, ClusterIP, external NodePort: 0 losses, max gaps 675/695/742 ms; installed by `helm install` alone |
| OVN-Kubernetes | OpenShift default | `ovn-kubernetes` | Phantom | ✓ (same Open vSwitch class as Antrea) | closed | not tested |
| Kube-OVN, kindnet, Multus (delegate) | various | own names | Phantom | ✓ | closed | not tested |

"closed" means: the connection cannot be kept. Paguro aborts it in the
pod right after the restore (`SOCK_DESTROY`): the migrated application gets
ECONNABORTED and can reconnect at once instead of hanging until a timeout.
The remote peer notices through its own retransmission timeout or
keepalive (the abort's RST would carry the old address, which the network
no longer routes).

### Why Phantom mode covers CNIs that cannot be run here

Phantom mode does not depend on the CNI's own datapath. Its programs sit on the
pod's **own interface inside the pod network namespace**, which every CNI
creates and none programs (docs/PHANTOM-MODE.md 4.1). The CNI only ever sees
the new IP. What differs between CNIs is *how traffic reaches the host*,
which matters only for host-network peers and kube-proxy NAT:

| Datapath class | CNIs | Host devices Paguro programs | Covered in the lab by |
|---|---|---|---|
| routed veth, no overlay | AWS VPC CNI, Azure CNI (transparent), Calico (no encapsulation) | uplink/ENIs (routes per pod; every ENI, see below) | Calico; namespace model (`e2e.sh`); EKS |
| veth + overlay device | Flannel (`flannel.1`), Calico VXLAN (`vxlan.calico`), Cilium (`cilium_vxlan`) | overlay device + uplink | Calico VXLAN, Cilium VXLAN, Flannel |
| bridge (`cni0`) | Flannel, kubenet-style | bridge + overlay | Flannel |
| Open vSwitch | Antrea, OVN-Kubernetes, Kube-OVN | gateway port (`antrea-gw0`, `ovn-k8s-mp0`) + OVS tunnel ports (`genev_sys_6081`, `vxlan_sys_4789`) | Antrea |

Two details of the Open vSwitch class, both found with Antrea:

* **Services inside OVS.** Antrea's proxy translates a pod's ClusterIP
  connection in OVS and tunnels it to the backend's node itself; the
  packet never passes a host interface on the way out. Paguro's host
  programs therefore also sit on the OVS tunnel ports, where they rewrite
  the inner destination and the tunnel endpoint (like with Cilium).
* **Spoof guard and symmetric paths.** OVS drops packets that leave a pod
  with a foreign source address, and it sends the replies of a connection
  that entered through the gateway back to the gateway. So a reply that
  must carry the old address is handed to the host stack (which returns
  it through the gateway port), and a client pod on the target node sends
  to the new address directly instead of via its gateway (the client's
  translation re-resolves the next hop). The hand-over to the host is
  used for CNIs that verify source addresses (Open vSwitch CNIs, Cilium);
  the next-hop fix wherever the new address is on the client's own
  segment – with Flannel's bridge too, not re-measured there yet. Pods of
  Calico and Cilium send everything through their gateway; nothing
  changes for them.

**Every routing table counts.** The AWS VPC CNI routes a pod whose
address belongs to a secondary ENI out of that ENI, with a rule of its own
(`ip rule`: `from <pod IP> lookup 2`; table 2: `default via … dev <ENI>`),
and the replies arrive there. The main table never names the ENI. Paguro
takes the host devices from the default routes and the routes to the old
and new address in every table, and its route watcher covers devices that
appear later (ipamd attaches ENIs as pods arrive). Measured on EKS before:
with programs on the primary ENI only, a client pod on a secondary ENI lost
every connection it had opened through a ClusterIP, on every migration,
while client pods on the primary ENI kept theirs.

Known limits:

* **AWS VPC CNI**: pod IPs are VPC addresses. Peers *inside the VPC but
  outside the cluster* (NLB/ALB in IP-target mode, other EC2 instances)
  reach the pod IP directly; Phantom mode cannot program them. Use
  `externalTrafficPolicy: Cluster` services (instance targets) for traffic
  that must survive a migration, or keep such pods out of migrations.
* **Cilium, Phantom mode**: NodePort/LoadBalancer connections through Cilium's
  eBPF load balancer are kept while Cilium still routes the old address
  as a cluster endpoint, i.e. while a node's pod CIDR covers it. A sticky
  /32 is released together with the source pod, so Phantom mode is refused for
  pods with a sticky IP (keeping the IP keeps every connection there).
  After a drained node is deleted, such connections cannot be kept; they
  are reset within seconds (the agents notice the old subnet's route
  vanish and the controller drops the address from the backend keeper)
  instead of hanging until the client's TCP timeout.
* **Cilium netkit mode**: the pod-side device is netkit; tc programs on it
  are not verified yet.
* IPv6: the datapath supports it; aborting unsupported IPv6 flows works,
  dual-stack pods are not tested on a cluster.

## Adding a CNI

1. Add its configuration format to `internal/netadapter/cniconf.go`
   (plugin type → name) and a sample to `cniconf_test.go`.
2. If it can move an IP between nodes, implement an `Adapter` (see
   `adapter.go`: Calico and Cilium) and return true from `MovableIP`.
3. Otherwise nothing else is needed: Phantom mode applies. If its host-side
   devices are not covered by the route lookup and the overlay list in
   `internal/phantom/discover.go`, add them there.
