// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
//
// Paguro Phantom network mode datapath.
//
// The datapath is an exact-match, bidirectional 5-tuple translator. It does
// not know anything about pods, nodes or migrations: the control plane
// (internal/phantom Go package) programs two tables,
//
//   xl_out: tuple of a packet LEAVING an endpoint (inside view)  -> wire tuple
//   xl_in:  tuple of a packet ARRIVING at an endpoint (wire view) -> inside view
//
// and attaches the programs below at the points where packets leave/enter an
// endpoint. An "endpoint" is either a pod network namespace (scope POD) or
// the host network stack of a node (scope HOST). Everything that is not an
// exact table hit is passed through untouched (TCX_NEXT / TC_ACT_UNSPEC), so
// the CNI's own programs that follow ours see exactly what they would have
// seen without Paguro.
//
// See docs/PHANTOM-MODE.md for the complete design.

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "include/bpf_helpers.h"
#include "include/bpf_endian.h"

#ifndef TCX_NEXT
#define TCX_NEXT -1
#endif

#define AF_INET 2
#define AF_INET6 10

#define XL_SCOPE_POD 1
#define XL_SCOPE_HOST 2

// Flags in xl_val.flags.
#define XL_F_PENDING (1U << 0)  // drop: endpoint not restored yet (target pod)
#define XL_F_REROUTE (1U << 1)  // host egress: re-route after rewriting daddr
#define XL_F_LOCAL (1U << 2)    // host-local delivery bypass (see xl_host_local)
#define XL_F_TUNNEL (1U << 3)   // rewrite collect_md tunnel remote (tunnel_remote4)
#define XL_F_NEIGH (1U << 4)    // pod egress: re-resolve the next hop after rewriting daddr

// Per-CPU statistics.
enum {
	XL_ST_SEEN = 0,     // packets that matched a rule
	XL_ST_XLATED,       // packets translated
	XL_ST_PENDING_DROP, // packets dropped because the flow is pending
	XL_ST_REROUTED,     // host egress packets redirected after re-routing
	XL_ST_LOCAL,        // packets delivered via the host-local bypass
	XL_ST_ERR,          // helper errors (packet passed through unmodified)
	XL_ST_TUNNEL,       // tunnel keys rewritten
	XL_ST_MAX,
};

struct xl_key {
	__u8 scope;
	__u8 proto;
	__u8 family;
	__u8 pad;
	__be16 sport;
	__be16 dport;
	__u8 saddr[16]; // IPv4: first 4 bytes, remaining bytes zero
	__u8 daddr[16];
};

struct xl_val {
	__u8 saddr[16];
	__u8 daddr[16];
	__be16 sport;
	__be16 dport;
	__u32 flags;
	__u32 tunnel_remote4; // host byte order, as used by bpf_tunnel_key
	__u32 owner;          // control plane tag (migration id), unused here
	__u64 packets; // updated by the datapath
	__u64 last_seen_ns; // bpf_ktime_get_ns() of the last hit (coarse)
};

struct ctl {
	__u32 enabled;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, struct xl_key);
	__type(value, struct xl_val);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} paguro_xl_out SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 262144);
	__type(key, struct xl_key);
	__type(value, struct xl_val);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} paguro_xl_in SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XL_ST_MAX);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} paguro_xl_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ctl);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} paguro_xl_ctl SEC(".maps");

// Offset of the network header: 14 for Ethernet devices (veth, physical
// NICs, vxlan, cilium_host), 0 for L3 devices (tunl0, wireguard, netkit in
// L3 mode). Set by the loader per program instance.
volatile const __u32 cfg_l3_off = ETH_HLEN;

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&paguro_xl_stats, &idx);
	if (v)
		*v += 1;
}

static __always_inline int enabled(void)
{
	__u32 k = 0;
	struct ctl *c = bpf_map_lookup_elem(&paguro_xl_ctl, &k);
	return c && c->enabled;
}

struct pkt {
	__u32 l3;      // offset of IP header
	__u32 l4;      // offset of L4 header
	__u32 csum;    // offset of L4 checksum
	__u8 family;
	__u8 proto;
	__u8 udp;
};

// parse fills key (without scope) and p. Returns 0 if the packet is a
// candidate for translation. Headers are read with direct packet access;
// if they are not in the linear area (rare for tc), they are pulled first.
static __always_inline int parse(struct __sk_buff *skb, struct xl_key *key, struct pkt *p)
{
	const __u32 l3 = cfg_l3_off;
	// Worst case header length we need: IPv6 + 4 bytes of ports.
	const __u32 need = l3 + sizeof(struct ipv6hdr) + 4;
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	__u16 proto;

	if (data + l3 + sizeof(struct iphdr) + 4 > end) {
		if (skb->len < l3 + sizeof(struct iphdr) + 4)
			return -1;
		if (bpf_skb_pull_data(skb, need < skb->len ? need : skb->len))
			return -1;
		data = (void *)(long)skb->data;
		end = (void *)(long)skb->data_end;
	}
	if (l3) {
		struct ethhdr *eth = data;
		if ((void *)(eth + 1) > end)
			return -1;
		proto = eth->h_proto;
	} else {
		proto = skb->protocol;
	}
	p->l3 = l3;

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + l3;
		if ((void *)(ip + 1) > end)
			return -1;
		if (ip->version != 4 || ip->ihl < 5)
			return -1;
		// Fragments: only the first one carries ports. We never translate
		// fragmented packets (see docs, "Limits").
		if (ip->frag_off & bpf_htons(0x3fff))
			return -1;
		if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
			return -1;
		p->family = AF_INET;
		p->proto = ip->protocol;
		p->l4 = l3 + ip->ihl * 4;
		__builtin_memcpy(key->saddr, &ip->saddr, 4);
		__builtin_memcpy(key->daddr, &ip->daddr, 4);
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + l3;
		if ((void *)(ip6 + 1) > end) {
			if (bpf_skb_pull_data(skb, need < skb->len ? need : skb->len))
				return -1;
			data = (void *)(long)skb->data;
			end = (void *)(long)skb->data_end;
			ip6 = data + l3;
			if ((void *)(ip6 + 1) > end)
				return -1;
		}
		if (ip6->version != 6)
			return -1;
		// No extension header walking: TCP/UDP must follow directly.
		if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP)
			return -1;
		p->family = AF_INET6;
		p->proto = ip6->nexthdr;
		p->l4 = l3 + sizeof(struct ipv6hdr);
		__builtin_memcpy(key->saddr, &ip6->saddr, 16);
		__builtin_memcpy(key->daddr, &ip6->daddr, 16);
	} else {
		return -1;
	}

	__u32 l4 = p->l4;
	if (l4 > 0xff) // keeps the verifier's range small (max l3 14 + 60)
		return -1;
	__be16 *ports = data + l4;
	if ((void *)(ports + 2) > end)
		return -1;
	key->sport = ports[0];
	key->dport = ports[1];
	key->proto = p->proto;
	key->family = p->family == AF_INET ? 4 : 6;
	p->udp = p->proto == IPPROTO_UDP;
	p->csum = p->l4 + (p->udp ? offsetof(struct udphdr, check) : offsetof(struct tcphdr, check));
	return 0;
}

static __always_inline int rewrite_addr4(struct __sk_buff *skb, struct pkt *p, __u32 off, __be32 from, __be32 to)
{
	__u64 l4flags = BPF_F_PSEUDO_HDR | sizeof(to);
	if (p->udp)
		l4flags |= BPF_F_MARK_MANGLED_0;
	if (bpf_l4_csum_replace(skb, p->csum, from, to, l4flags))
		return -1;
	if (bpf_l3_csum_replace(skb, p->l3 + offsetof(struct iphdr, check), from, to, sizeof(to)))
		return -1;
	return bpf_skb_store_bytes(skb, off, &to, sizeof(to), 0);
}

static __always_inline int rewrite_addr6(struct __sk_buff *skb, struct pkt *p, __u32 off, __u8 *from, __u8 *to)
{
	__s64 diff = bpf_csum_diff((__be32 *)from, 16, (__be32 *)to, 16, 0);
	__u64 l4flags = BPF_F_PSEUDO_HDR;
	if (p->udp)
		l4flags |= BPF_F_MARK_MANGLED_0;
	if (diff < 0)
		return -1;
	if (bpf_l4_csum_replace(skb, p->csum, 0, (__u32)diff, l4flags))
		return -1;
	return bpf_skb_store_bytes(skb, off, to, 16, 0);
}

static __always_inline int rewrite_port(struct __sk_buff *skb, struct pkt *p, __u32 off, __be16 from, __be16 to)
{
	__u64 l4flags = sizeof(to);
	if (p->udp)
		l4flags |= BPF_F_MARK_MANGLED_0;
	if (bpf_l4_csum_replace(skb, p->csum, from, to, l4flags))
		return -1;
	return bpf_skb_store_bytes(skb, off, &to, sizeof(to), 0);
}

static __always_inline int addr_eq(const __u8 *a, const __u8 *b, int n)
{
	for (int i = 0; i < n; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

// apply rewrites the packet from the tuple in key to the tuple in v.
static __always_inline int apply(struct __sk_buff *skb, struct pkt *p, struct xl_key *key, struct xl_val *v)
{
	int err = 0;

	if (p->family == AF_INET) {
		__be32 os, od, ns, nd;
		__builtin_memcpy(&os, key->saddr, 4);
		__builtin_memcpy(&od, key->daddr, 4);
		__builtin_memcpy(&ns, v->saddr, 4);
		__builtin_memcpy(&nd, v->daddr, 4);
		if (os != ns)
			err |= rewrite_addr4(skb, p, p->l3 + offsetof(struct iphdr, saddr), os, ns);
		if (od != nd)
			err |= rewrite_addr4(skb, p, p->l3 + offsetof(struct iphdr, daddr), od, nd);
	} else {
		if (!addr_eq(key->saddr, v->saddr, 16))
			err |= rewrite_addr6(skb, p, p->l3 + offsetof(struct ipv6hdr, saddr), key->saddr, v->saddr);
		if (!addr_eq(key->daddr, v->daddr, 16))
			err |= rewrite_addr6(skb, p, p->l3 + offsetof(struct ipv6hdr, daddr), key->daddr, v->daddr);
	}
	if (key->sport != v->sport)
		err |= rewrite_port(skb, p, p->l4, key->sport, v->sport);
	if (key->dport != v->dport)
		err |= rewrite_port(skb, p, p->l4 + 2, key->dport, v->dport);

	if (err) {
		stat_inc(XL_ST_ERR);
		return -1;
	}
	stat_inc(XL_ST_XLATED);
	return 0;
}

static __always_inline void touch(struct xl_val *v)
{
	__u64 now = bpf_ktime_get_ns();
	__sync_fetch_and_add(&v->packets, 1);
	// Only write last_seen about once per second to keep the cache line
	// mostly read-only.
	if (now - v->last_seen_ns > 1000000000ULL)
		v->last_seen_ns = now;
}

static __always_inline struct xl_val *lookup(struct __sk_buff *skb, void *map, __u8 scope, struct xl_key *key, struct pkt *p)
{
	__builtin_memset(key, 0, sizeof(*key));
	if (!enabled())
		return 0;
	if (parse(skb, key, p))
		return 0;
	key->scope = scope;
	struct xl_val *v = bpf_map_lookup_elem(map, key);
	if (v)
		stat_inc(XL_ST_SEEN);
	return v;
}

// ---------------------------------------------------------------------------
// Pod endpoint programs.
//
// xl_pod_out runs where packets LEAVE a pod: tc/TCX egress of the pod's own
// interface inside the pod netns (preferred), or tc/TCX ingress of the
// host-side veth (anchored at the head, before the CNI).
// xl_pod_in runs where packets ENTER a pod: tc/TCX ingress of the pod's own
// interface inside the pod netns (preferred; this hook also sees packets the
// CNI delivered with bpf_redirect_peer), or tc/TCX egress of the host-side veth.
// ---------------------------------------------------------------------------

// renext4 sends the frame on to the rewritten destination: the pod chose
// the next hop for OLD – its gateway when OLD was on another node – but NEW
// is on the pod's own segment (the peer runs on the target node; the
// control plane checked the route, FlagNeigh). Addressed to the gateway,
// the frame would hairpin through the host: asymmetric, and Open vSwitch
// CNIs (Antrea) route the replies of a connection that entered through the
// gateway back to the gateway, where they are lost.
//
// Without next-hop parameters the helper routes the rewritten packet itself
// (an output route lookup, which needs no forwarding – bpf_fib_lookup does,
// and forwarding is off inside pods) and replaces the packet's route.
// Giving NEW as the next hop instead fails for the first packet: it waits
// for address resolution, and the neighbour code then sends it along its
// original route – to the gateway. The frame re-enters this hook once and
// passes: the rewritten tuple is no rule.
static __always_inline int renext4(struct __sk_buff *skb)
{
	stat_inc(XL_ST_REROUTED);
	return bpf_redirect_neigh(skb->ifindex, 0, 0, 0);
}

static __always_inline int pod_out(struct __sk_buff *skb, int in_pod)
{
	struct xl_key key;
	struct pkt p = {};
	struct xl_val *v = lookup(skb, &paguro_xl_out, XL_SCOPE_POD, &key, &p);
	if (!v)
		return TCX_NEXT;
	touch(v);
	if (apply(skb, &p, &key, v))
		return TCX_NEXT;
	if (in_pod && (v->flags & XL_F_NEIGH) && p.family == AF_INET && cfg_l3_off) {
		// Only a changed destination needs a new next hop; an unchanged
		// one would make the redirected packet match this rule again.
		__u32 od, nd;
		__builtin_memcpy(&od, key.daddr, 4);
		__builtin_memcpy(&nd, v->daddr, 4);
		if (od != nd)
			return renext4(skb);
	}
	return TCX_NEXT;
}

// xl_pod_out: egress of the pod's own interface, inside the pod netns.
SEC("tc")
int xl_pod_out(struct __sk_buff *skb)
{
	return pod_out(skb, 1);
}

// xl_podhost_out: ingress of the host-side veth (fallback). The next hop
// cannot be fixed from there: the host's view is not the pod's.
SEC("tc")
int xl_podhost_out(struct __sk_buff *skb)
{
	return pod_out(skb, 0);
}

SEC("tc")
int xl_pod_in(struct __sk_buff *skb)
{
	struct xl_key key;
	struct pkt p = {};
	struct xl_val *v = lookup(skb, &paguro_xl_in, XL_SCOPE_POD, &key, &p);
	if (!v)
		return TCX_NEXT;
	if (v->flags & XL_F_PENDING) {
		// The restored socket does not exist yet. Dropping (instead of
		// letting the pod kernel answer with RST) makes the peer
		// retransmit, exactly like during the CRIU freeze.
		stat_inc(XL_ST_PENDING_DROP);
		return TC_ACT_SHOT;
	}
	touch(v);
	apply(skb, &p, &key, v);
	return TCX_NEXT;
}

// ---------------------------------------------------------------------------
// Host endpoint programs (host network namespace of a node).
// ---------------------------------------------------------------------------

// fib4 does a FIB lookup from the ingress perspective of the current device.
// (With BPF_FIB_LOOKUP_OUTPUT the ifindex becomes a strict output-interface
// constraint, which is exactly what we do not want when re-routing.) Node
// devices of a Kubernetes node always have forwarding enabled.
static __always_inline long fib4(struct __sk_buff *skb, struct bpf_fib_lookup *f, __be32 src, __be32 dst, __u8 proto)
{
	__builtin_memset(f, 0, sizeof(*f));
	f->family = AF_INET;
	f->l4_protocol = proto;
	f->ipv4_src = src;
	f->ipv4_dst = dst;
	f->ifindex = skb->ifindex;
	return bpf_fib_lookup(skb, f, sizeof(*f), 0);
}

// reroute4 makes sure a packet whose destination we rewrote after the host's
// routing decision leaves through the device/next hop of the NEW address.
// If the FIB says "same device", the L2 header is fixed in place and the
// packet continues down the TCX chain (so the CNI's program on this device
// still runs). Otherwise it is redirected to the right device.
static __always_inline int reroute4(struct __sk_buff *skb, struct pkt *p, struct xl_val *v)
{
	struct bpf_fib_lookup f;
	__be32 src, dst;
	__builtin_memcpy(&src, v->saddr, 4);
	__builtin_memcpy(&dst, v->daddr, 4);

	long rc = fib4(skb, &f, src, dst, p->proto);
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		if (f.ifindex == skb->ifindex) {
			if (cfg_l3_off) {
				bpf_skb_store_bytes(skb, 0, f.dmac, ETH_ALEN, 0);
				bpf_skb_store_bytes(skb, ETH_ALEN, f.smac, ETH_ALEN, 0);
			}
			return TCX_NEXT;
		}
		stat_inc(XL_ST_REROUTED);
		struct bpf_redir_neigh nh = { .nh_family = AF_INET, .ipv4_nh = f.ipv4_dst };
		return bpf_redirect_neigh(f.ifindex, &nh, sizeof(nh), 0);
	}
	if (rc == BPF_FIB_LKUP_RET_NO_NEIGH) {
		// Next hop not resolved yet (or a different next hop on the same
		// device): let the kernel resolve it. A redirect to the same
		// device's egress re-enters this program, which then passes (the
		// rewritten tuple is not in the table).
		stat_inc(XL_ST_REROUTED);
		struct bpf_redir_neigh nh = { .nh_family = AF_INET, .ipv4_nh = f.ipv4_dst };
		return bpf_redirect_neigh(f.ifindex, &nh, sizeof(nh), 0);
	}
	return TCX_NEXT;
}

static __always_inline void retunnel(struct __sk_buff *skb, struct xl_val *v)
{
	struct bpf_tunnel_key tk = {};
	if (bpf_skb_get_tunnel_key(skb, &tk, sizeof(tk), 0))
		return;
	tk.remote_ipv4 = v->tunnel_remote4;
	if (bpf_skb_set_tunnel_key(skb, &tk, sizeof(tk), BPF_F_ZERO_CSUM_TX) == 0)
		stat_inc(XL_ST_TUNNEL);
	else
		stat_inc(XL_ST_ERR);
}

// xl_host_out: tc/TCX egress (head) of the node devices that carry pod
// traffic (uplink, overlay device, cilium_host, ...). Translates packets the
// host stack emitted after routing: host-network clients and flows that
// netfilter/kube-proxy DNAT'ed to the old pod address.
SEC("tc")
int xl_host_out(struct __sk_buff *skb)
{
	struct xl_key key;
	struct pkt p = {};
	struct xl_val *v = lookup(skb, &paguro_xl_out, XL_SCOPE_HOST, &key, &p);
	if (!v)
		return TCX_NEXT;
	touch(v);
	if (apply(skb, &p, &key, v))
		return TCX_NEXT;
	if ((v->flags & XL_F_TUNNEL) && v->tunnel_remote4)
		retunnel(skb, v);
	if ((v->flags & XL_F_REROUTE) && p.family == AF_INET)
		return reroute4(skb, &p, v);
	return TCX_NEXT;
}

// xl_host_in: tc/TCX ingress (head) of the same node devices. Translates
// replies for host-scope flows before netfilter/conntrack and the host
// sockets see them.
SEC("tc")
int xl_host_in(struct __sk_buff *skb)
{
	struct xl_key key;
	struct pkt p = {};
	struct xl_val *v = lookup(skb, &paguro_xl_in, XL_SCOPE_HOST, &key, &p);
	if (!v || (v->flags & XL_F_LOCAL))
		return TCX_NEXT;
	touch(v);
	apply(skb, &p, &key, v);
	return TCX_NEXT;
}

// xl_host_local: tc/TCX ingress (head) of the migrated pod's HOST-side veth on
// the target node. Handles host-scope flows whose host endpoint lives on the
// target node itself (kubelet, hostNetwork pods). After translation the
// source is the OLD address, which a CNI with source verification (Cilium)
// or a strict rp_filter on the veth would drop, so the packet is handed to
// the host stack on another device instead of continuing on the veth.
SEC("tc")
int xl_host_local(struct __sk_buff *skb)
{
	struct xl_key key;
	struct pkt p = {};
	struct xl_val *v = lookup(skb, &paguro_xl_in, XL_SCOPE_HOST, &key, &p);
	if (!v || !(v->flags & XL_F_LOCAL))
		return TCX_NEXT;
	touch(v);
	if (apply(skb, &p, &key, v))
		return TCX_NEXT;

	// Re-inject the packet on the device the host routes the (translated)
	// source through, i.e. where packets of this connection used to arrive
	// before the migration: reverse-path filtering then agrees, and the
	// socket's cached input route (early demux) still matches. Fallback: lo.
	__u32 target = 1; // lo
	__u8 mac[ETH_ALEN] = {};
	if (p.family == AF_INET) {
		struct bpf_fib_lookup f;
		__be32 src, dst;
		__builtin_memcpy(&src, v->saddr, 4);
		__builtin_memcpy(&dst, v->daddr, 4);
		long rc = fib4(skb, &f, dst, src, p.proto);
		if ((rc == BPF_FIB_LKUP_RET_SUCCESS || rc == BPF_FIB_LKUP_RET_NO_NEIGH) && f.ifindex != skb->ifindex) {
			target = f.ifindex;
			__builtin_memcpy(mac, f.smac, ETH_ALEN); // the device's own MAC
		}
	}
	if (cfg_l3_off) {
		// eth_type_trans() on the target marks frames not addressed to its
		// MAC as PACKET_OTHERHOST, which IP drops (lo: all-zero MAC).
		bpf_skb_store_bytes(skb, 0, mac, ETH_ALEN, 0);
	}
	stat_inc(XL_ST_LOCAL);
	return bpf_redirect(target, BPF_F_INGRESS);
}

char __license[] SEC("license") = "Dual BSD/GPL";
