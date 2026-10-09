#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Phantom mode, UDP servers behind a NodePort with MASQUERADE --random-fully
# (docs/PHANTOM-MODE.md, "UDP servers"): the NAT bindings of the server's clients
# move to the new pod IP on the entry node and keep the masquerade port.
#
# The namespace model of topology.sh, reduced to what this case needs and
# with its own names (pgu-*), so that it can run next to e2e.sh:
#
#                     pgu-r (router, bridge br0 192.168.51.254/24)
#        ┌─────────────────┬───────────────┼──────────────────┐
#   pgu-na .1         pgu-no .2       pgu-nt .3          pgu-ext .100
#   entry node A      old node        target node        "outside" player
#   pod pgu-pa        pod pgu-po      (the server's namespace moves here:
#   10.245.1.10       OLD 10.245.2.10  NEW 10.245.3.20, OLD on lo)
#
# A UDP game server (udpgame.py: one unconnected socket, players known by
# the address their datagrams come from) runs in the OLD pod. Players:
#   p1  pgu-ext -> NodePort 192.168.51.1:30260 on A: DNAT + MASQUERADE --random-fully
#   p2  pgu-pa  -> "ClusterIP" 10.97.0.20:26000 on A: DNAT, no masquerade
# kube-proxy is modelled on A with iptables-legacy. The migration is
# simulated without CRIU, like e2e.sh -mode replumb: the server is stopped,
# the agent on A records the bindings (the commit), the server's namespace
# is re-wired to the target node, A moves the bindings (the target reported
# the new IP), the restore's UDP hold goes up in the pod, the server goes on.
# Then kube-proxy on A switches the Service to NEW and deletes the UDP
# entries whose reply comes from OLD (its stale-endpoint clean-up), and 2 s
# later the entries to NEW as well (a clean-up that ran before it counted
# NEW as serving): the move keeps the bindings through both.
#
#   sudo udp-rebind.sh [-no-rebind] [-no-hold] [-keep]
#
# -no-rebind  negative control: nothing moved – p1 must lose its session
#             (the server sees it from another port), p2 must keep it.
# -no-hold    no hold in the restored pod, and A moves the bindings only after
#             the restore: the server writes to p1 first; the move must clear
#             the entry that datagram opens on A.
# -keep       leave the namespaces and processes for inspection
#             (udp-rebind.sh down removes them).
#
# Needs: python3, iptables-legacy, conntrack, nft, and the paguro-udprebind-test
# binary in $UDPREBIND (default: in PATH):
#   go build -o /usr/local/bin/paguro-udprebind-test ./hack/udprebind-test
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
UDPREBIND=${UDPREBIND:-paguro-udprebind-test}
PY=${PY:-/usr/bin/python3}
GAME="$HERE/udpgame.py"
W=${WORKDIR:-/tmp/pgu-udp-rebind}
REBIND=1
HOLD=1
KEEP=0

OLD=10.245.2.10
NEW=10.245.3.20
NS="pgu-r pgu-na pgu-no pgu-nt pgu-ext pgu-pa pgu-po"
IPT="iptables-legacy -w"

x() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
log() { printf '\n=== %s\n' "$*"; }
bg() { local name=$1 ns=$2; shift 2; setsid ip netns exec "$ns" "$@" </dev/null >"$W/$name.log" 2>&1 & echo $! >"$W/$name.pid"; }

down() { for n in $NS; do ip netns del "$n" 2>/dev/null || true; done; }

node() { # name idx
	local n=$1 i=$2
	ip netns add "$n"
	ip link add "u-$n" type veth peer name uplink netns "$n"
	ip link set "u-$n" netns pgu-r
	x pgu-r ip link set "u-$n" master br0 up
	x "$n" ip link set lo up
	x "$n" ip addr add "192.168.51.$i/24" dev uplink
	x "$n" ip link set uplink up
	x "$n" sysctl -qw net.ipv4.ip_forward=1
	x "$n" sysctl -qw net.ipv4.conf.all.rp_filter=1
	x "$n" sysctl -qw net.ipv4.conf.default.rp_filter=1
	[ "$i" = 100 ] && return 0 # outside player: only knows the LAN
	x "$n" ip route add default via 192.168.51.254
	for j in 1 2 3; do
		[ "$j" = "$i" ] || x "$n" ip route add "10.245.$j.0/24" via "192.168.51.$j"
	done
}

# veth of a pod: /32 on eth0, default via 169.254.1.1 onlink (like Calico).
plug() { # podns nodens hostif ip
	local p=$1 n=$2 h=$3 ip=$4
	ip -n "$n" link add "$h" type veth peer name eth0 netns "$p"
	x "$n" ip link set "$h" up
	x "$n" sysctl -qw "net.ipv4.conf.$h.proxy_arp=1"
	x "$n" sysctl -qw "net.ipv4.conf.$h.rp_filter=1"
	x "$n" ip route replace "$ip/32" dev "$h"
	x "$p" ip addr add "$ip/32" dev eth0
	x "$p" ip link set eth0 up
	x "$p" ip route add 169.254.1.1 dev eth0 scope link
	x "$p" ip route add default via 169.254.1.1 dev eth0 onlink
}

up() {
	down
	ip netns add pgu-r
	x pgu-r ip link set lo up
	x pgu-r ip link add br0 type bridge
	x pgu-r ip addr add 192.168.51.254/24 dev br0
	x pgu-r ip link set br0 up
	node pgu-na 1
	node pgu-no 2
	node pgu-nt 3
	node pgu-ext 100
	for p in pgu-pa pgu-po; do ip netns add "$p"; x "$p" ip link set lo up; done
	plug pgu-pa pgu-na h-pa 10.245.1.10
	plug pgu-po pgu-no h-po "$OLD"
	# kube-proxy on A: the Service's rules in chains of their own, so that
	# the endpoint can be switched.
	x pgu-na $IPT -t nat -N PGU-SVC
	x pgu-na $IPT -t nat -N PGU-MASQ
	x pgu-na $IPT -t nat -A PREROUTING -j PGU-SVC
	x pgu-na $IPT -t nat -A POSTROUTING -j PGU-MASQ
	service "$OLD"
}

service() { # endpoint
	x pgu-na $IPT -t nat -F PGU-SVC
	x pgu-na $IPT -t nat -A PGU-SVC -d 192.168.51.1 -p udp --dport 30260 -j DNAT --to-destination "$1:26000"
	x pgu-na $IPT -t nat -A PGU-SVC -d 10.97.0.20 -p udp --dport 26000 -j DNAT --to-destination "$1:26000"
	x pgu-na $IPT -t nat -F PGU-MASQ
	x pgu-na $IPT -t nat -A PGU-MASQ -s 192.168.51.0/24 -d "$1" -p udp --dport 26000 -j MASQUERADE --random-fully
}

# The server's namespace moves to the target node: eth0 = NEW, OLD on lo
# (what the restore does in the new pod).
replumb() {
	x pgu-no ip link del h-po
	x pgu-no ip route del "$OLD/32" 2>/dev/null || true
	x pgu-po sysctl -qw net.ipv4.conf.all.arp_announce=2
	x pgu-po ip addr add "$OLD/32" dev lo
	plug pgu-po pgu-nt h-pm "$NEW"
}

# The restore's hold (shield.HoldUDPReplies): the server's datagrams that
# would open a conntrack entry are dropped for 30 s.
hold() {
	x pgu-po nft -f - <<EOF
table inet paguro_udp_hold_test {
	chain out {
		type filter hook output priority 0; policy accept;
		udp sport { 26000 } ct state new meta time < $(($(date +%s) + 30)) counter drop
	}
}
EOF
}

stop() { for p in "$W"/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true; done; }

cleanup() {
	[ "$KEEP" = 1 ] && return 0
	stop
	down
}

case "${1:-}" in
down) stop; down; exit 0 ;;
esac
while [ $# -gt 0 ]; do
	case $1 in
	-no-rebind) REBIND=0 ;;
	-no-hold) HOLD=0 ;;
	-keep) KEEP=1 ;;
	*) echo "usage: $0 [-no-rebind] [-no-hold] [-keep] | down" >&2; exit 2 ;;
	esac
	shift
done
command -v "$UDPREBIND" >/dev/null || { echo "$UDPREBIND not found (see the header)" >&2; exit 2; }

trap cleanup EXIT
rm -rf "$W" && mkdir -p "$W"
up

log "server in the OLD pod ($OLD:26000), p1 through the NodePort (masquerade), p2 through the ClusterIP"
bg server pgu-po "$PY" "$GAME" serve --port 26000 --report "$W/server.json"
sleep 0.5
bg p1 pgu-ext "$PY" "$GAME" play 192.168.51.1:30260 --id 1 --report "$W/p1.json"
bg p2 pgu-pa "$PY" "$GAME" play 10.97.0.20:26000 --id 2 --report "$W/p2.json"
sleep 3
x pgu-na conntrack -L -p udp 2>/dev/null | sed 's/^/  /'

bg ct-events pgu-na conntrack -E -p udp -o timestamp
SPID=$(cat "$W/server.pid")
log "freeze the server; the agent on A records the bindings (commit)"
kill -STOP "$SPID"
T0=$(date +%s.%N)
if [ "$REBIND" = 1 ]; then
	bg rebind pgu-na "$UDPREBIND" move -old "$OLD" -new "$NEW" -ports 26000 -after "$W/programmed" -for 25s
	sleep 0.3
fi
log "re-wire the server's namespace to the target node (NEW $NEW, OLD on lo)"
replumb
if [ "$HOLD" = 1 ]; then
	# The hold goes up before the restore; the target reported the new IP
	# before it, too: A moves the bindings.
	hold
	touch "$W/programmed"
	sleep 0.3
	log "restore: the server goes on"
	kill -CONT "$SPID"
else
	# No hold, and A moves the bindings only after the restore: the server
	# writes to p1's masquerade binding first.
	log "restore without hold: the server goes on and writes first"
	kill -CONT "$SPID"
	sleep 0.5
	touch "$W/programmed"
fi
T1=$(date +%s.%N)
awk -v a="$T0" -v b="$T1" 'BEGIN{printf "freeze %.0f ms\n",(b-a)*1000}'

sleep 1
log "kube-proxy on A: Service -> NEW, UDP entries from OLD deleted"
service "$NEW"
x pgu-na conntrack -D -p udp --reply-src "$OLD" 2>&1 | sed 's/^/  /' || true
sleep 2
log "kube-proxy on A once more: UDP entries from NEW deleted (NEW not yet serving)"
date +%s.%N >"$W/second-cleanup"
x pgu-na conntrack -D -p udp --reply-src "$NEW" 2>&1 | sed 's/^/  /' || true
sleep 6

log "results"
set +e
fail=0
progress() { "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["received"])' "$1"; }
b1=$(progress "$W/p1.json"); b2=$(progress "$W/p2.json")
sleep 2
check() { # id description expect(ok|broken)
	local id=$1 name=$2 want=$3 before=$4 got
	got=$("$PY" - "$W/p$id.json" "$W/server.json" "$id" "$before" <<'EOF2'
import json, sys
p = json.load(open(sys.argv[1]))
srv = json.load(open(sys.argv[2])).get(sys.argv[3], {})
progress = p["received"] - int(sys.argv[4])
strangers = sum(srv.get("strangers", {}).values())
# A stranger datagram or two may slip through while kube-proxy's second
# clean-up and the re-install race (one client interval, 33 ms); a lost
# binding shows as hundreds and as a player without replies.
bad = progress <= 0 or p["timed_out"] or strangers > 5
print("  player: received=%d max_gap=%.0fms timed_out=%s; progress in the last 2 s: %d" % (p["received"], p["max_gap_ms"], p["timed_out"], progress))
print("  server: knows it as %s, inputs answered %d, datagrams from other addresses: %d %s" % (srv.get("addr"), srv.get("inputs", 0), strangers, sorted(srv.get("strangers", {}))))
print("RESULT", "broken" if bad else "ok")
EOF2
)
	echo "$name (expect $want):"
	echo "$got" | grep -v RESULT
	if [ "$(echo "$got" | awk '/RESULT/{print $2}')" != "$want" ]; then echo "  -> UNEXPECTED"; fail=1; fi
}
if [ "$REBIND" = 1 ]; then
	check 1 "p1 outside -> NodePort, MASQUERADE --random-fully" ok "$b1"
else
	check 1 "p1 outside -> NodePort, MASQUERADE --random-fully, nothing moved" broken "$b1"
fi
check 2 "p2 pod -> ClusterIP, no masquerade" ok "$b2"
log "conntrack on A"
x pgu-na conntrack -L -p udp 2>/dev/null | sed 's/^/  /'
if [ "$REBIND" = 1 ]; then
	log "binding moves on A"
	sed 's/^/  /' "$W/rebind.log"
fi
[ "$HOLD" = 1 ] && { log "hold in the new pod"; x pgu-po nft list table inet paguro_udp_hold_test | grep counter | sed 's/^/  /'; }

[ "$fail" = 0 ] && log "PASS" || { log "FAIL"; exit 1; }
