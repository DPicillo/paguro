#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Network-namespace model of a 3-node cluster for the Phantom-mode tests.
#
#                       pgr-r (router, bridge br0 192.168.50.254/24)
#        ┌──────────────────┬───────────────┼──────────────────┬───────────────┐
#   pgr-na .1          pgr-no .2       pgr-nt .3            pgr-ext .100
#   node A             old node        target node          "outside" client
#   pods:              pods:           pods:
#    pgr-pa  10.244.1.10  pgr-po 10.244.2.10 (OLD)   pgr-pm 10.244.3.20 (NEW, OLD on lo)
#    pgr-pa2 10.244.1.11                            pgr-pt 10.244.3.30 (same-node peer)
#
# Pods attach like Calico: /32 on eth0, default via 169.254.1.1 onlink,
# host side h-<pod> with proxy_arp and strict rp_filter (anti-spoofing, as a
# CNI source check would do). Nodes route other nodes' /24 via the node IP.
# kube-proxy-like rules on node A: ClusterIP 10.96.0.10:80 -> OLD:7004 and
# NodePort 192.168.50.1:30080 -> OLD:7005 with masquerade.
#
#   topology.sh up | down
set -euo pipefail

NS="pgr-r pgr-na pgr-no pgr-nt pgr-ext pgr-pa pgr-pa2 pgr-po pgr-pm pgr-pt pgr-po2"
OLD=10.244.2.10
NEW=10.244.3.20

x() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

down() {
	for n in $NS; do ip netns del "$n" 2>/dev/null || true; done
}

node() { # name idx
	local n=$1 i=$2
	ip netns add "$n"
	ip link add "u-$n" type veth peer name uplink netns "$n"
	ip link set "u-$n" netns pgr-r
	x pgr-r ip link set "u-$n" master br0 up
	x "$n" ip link set lo up
	x "$n" ip addr add "192.168.50.$i/24" dev uplink
	x "$n" ip link set uplink up
	x "$n" sysctl -qw net.ipv4.ip_forward=1
	x "$n" sysctl -qw net.ipv4.conf.all.rp_filter=1
	x "$n" sysctl -qw net.ipv4.conf.default.rp_filter=1
	[ "$i" = 100 ] && return 0 # outside client: only knows the LAN
	# A default route makes proxy_arp answer the pods' 169.254.1.1 queries.
	x "$n" ip route add default via 192.168.50.254
	for j in 1 2 3; do
		[ "$j" = "$i" ] || x "$n" ip route add "10.244.$j.0/24" via "192.168.50.$j"
	done
}

# What the agent does in a restored pod (docs/PHANTOM-MODE.md, integration):
# OLD goes on lo so the restored sockets can bind to it, and arp_announce=2
# so ARP requests carry the NEW address (otherwise "who-has gw tell OLD" is
# refused by proxy-ARP/rp_filter on the node side).
migrated_pod() { # podns oldip
	x "$1" sysctl -qw net.ipv4.conf.all.arp_announce=2
	x "$1" sysctl -qw net.ipv4.conf.default.arp_announce=2
	x "$1" ip addr add "$2/32" dev lo
}

pod() { # podns nodens ip [extra-lo-ip]
	local p=$1 n=$2 ip=$3 lo=${4:-}
	ip netns add "$p"
	ip link add "h-${p#pgr-}" type veth peer name eth0 netns "$p"
	ip link set "h-${p#pgr-}" netns "$n"
	x "$n" ip link set "h-${p#pgr-}" up
	x "$n" sysctl -qw "net.ipv4.conf.h-${p#pgr-}.proxy_arp=1"
	x "$n" sysctl -qw "net.ipv4.conf.h-${p#pgr-}.rp_filter=1"
	x "$n" ip route add "$ip/32" dev "h-${p#pgr-}"
	x "$p" ip link set lo up
	x "$p" ip addr add "$ip/32" dev eth0
	x "$p" ip link set eth0 up
	x "$p" ip route add 169.254.1.1 dev eth0 scope link
	x "$p" ip route add default via 169.254.1.1 dev eth0 onlink
	if [ -n "$lo" ]; then migrated_pod "$p" "$lo"; fi
}

up() {
	down
	ip netns add pgr-r
	x pgr-r ip link set lo up
	x pgr-r ip link add br0 type bridge
	x pgr-r ip addr add 192.168.50.254/24 dev br0
	x pgr-r ip link set br0 up
	node pgr-na 1
	node pgr-no 2
	node pgr-nt 3
	node pgr-ext 100
	pod pgr-pa pgr-na 10.244.1.10
	pod pgr-pa2 pgr-na 10.244.1.11
	pod pgr-po pgr-no "$OLD"
	pod pgr-pm pgr-nt "$NEW" "$OLD"
	pod pgr-pt pgr-nt 10.244.3.30
	# kube-proxy-like NAT on node A (iptables-legacy keeps it independent
	# of nft on the machine; it only exists inside pgr-na).
	local IPT=iptables-legacy
	x pgr-na $IPT -t nat -A PREROUTING -d 10.96.0.10 -p tcp --dport 80 -j DNAT --to-destination "$OLD:7004"
	x pgr-na $IPT -t nat -A OUTPUT -d 10.96.0.10 -p tcp --dport 80 -j DNAT --to-destination "$OLD:7004"
	x pgr-na $IPT -t nat -A PREROUTING -d 192.168.50.1 -p tcp --dport 30080 -j DNAT --to-destination "$OLD:7005"
	x pgr-na $IPT -t nat -A POSTROUTING -s 192.168.50.0/24 -d "$OLD" -p tcp --dport 7005 -j MASQUERADE
	# Old node masquerades pod egress to the "outside" (pgr-ext).
	x pgr-no $IPT -t nat -A POSTROUTING -s 10.244.0.0/16 -d 192.168.50.100 -j MASQUERADE
	x pgr-nt $IPT -t nat -A POSTROUTING -s 10.244.0.0/16 -d 192.168.50.100 -j MASQUERADE
}

offload() { # on|off: tx checksum offload on every veth
	for n in $NS; do
		for d in $(ip -n "$n" -o link show type veth 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 || true); do
			ip netns exec "$n" ethtool -K "$d" tx "$1" >/dev/null 2>&1 || true
		done
	done
}

# replumb: CRIU-free migration of pgr-po's namespace to the target node.
# The old veth must already be gone. Afterwards pgr-po looks exactly like a
# restored pod: eth0 = NEW (via h-pm on pgr-nt), OLD on lo.
replumb() {
	x pgr-nt ip link del h-pm 2>/dev/null || true
	ip netns del pgr-pm 2>/dev/null || true
	ip -n pgr-nt link add h-pm type veth peer name eth0 netns pgr-po
	x pgr-nt ip link set h-pm up
	x pgr-nt sysctl -qw net.ipv4.conf.h-pm.proxy_arp=1
	x pgr-nt sysctl -qw net.ipv4.conf.h-pm.rp_filter=1
	x pgr-nt ip route replace "$NEW/32" dev h-pm
	migrated_pod pgr-po "$OLD"
	x pgr-po ip addr add "$NEW/32" dev eth0
	x pgr-po ip link set eth0 up
	x pgr-po ip route add 169.254.1.1 dev eth0 scope link
	x pgr-po ip route add default via 169.254.1.1 dev eth0 onlink
}

case "${1:-}" in
up) up ;;
replumb) replumb ;;
down) down ;;
offload) offload "$2" ;;
*) echo "usage: $0 up|down|replumb|offload on|off" >&2; exit 2 ;;
esac
