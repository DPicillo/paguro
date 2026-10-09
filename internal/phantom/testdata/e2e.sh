#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# End-to-end test of the Phantom-mode datapath with a real CRIU migration.
#
# Uses the namespace model from topology.sh. A server process with eight
# long-lived TCP streams (every flow class of docs/PHANTOM-MODE.md) is
# checkpointed with `criu dump --tcp-established` in the old pod and restored
# in the new pod, which has a different IP. The rules are computed by
# `paguro-phantom-test plan` per simulated node (each node has its own bpffs
# pin directory, i.e. its own maps).
#
#   sudo e2e.sh [-mode criu|replumb] [-legacy] [-offload off] [-keep]
#
# -mode criu    (default) real checkpoint/restore into pgr-pm.
# -mode replumb CRIU-free simulation: the server keeps running in its
#               namespace while the namespace is re-wired from the old node
#               to the target node (eth0 = NEW, OLD on lo). This is exactly
#               the network situation after a restore; used where CRIU cannot
#               run (e.g. under a seccomp sandbox).
#
# Needs: criu, python3, iptables-legacy, tcpdump, the paguro-phantom-test
# binary in $PHANTOM_TEST (default: paguro-phantom-test in PATH).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
PHANTOM_TEST=${PHANTOM_TEST:-paguro-phantom-test}
PY=${PY:-/usr/bin/python3}
FC="$HERE/flowcheck.py"
W=${WORKDIR:-/tmp/pgr-e2e}
LEGACY=""
NORES=""
OFFLOAD=on
KEEP=0
MODE=criu
while [ $# -gt 0 ]; do
	case $1 in
	-mode) MODE=$2; shift ;;
	-legacy) LEGACY=-legacy ;;
	-offload) OFFLOAD=$2; shift ;;
	-keep) KEEP=1 ;;
	-no-reservations) NORES=-no-reservations ;; # negative control: expect collisions
	esac
	shift
done

OLD=10.244.2.10
NEW=10.244.3.20
PIN=/sys/fs/bpf/pgr
NETS="-cluster-net 10.244.0.0/16 -cluster-net 10.96.0.0/12 -cluster-net 192.168.50.1/32 -cluster-net 192.168.50.2/32 -cluster-net 192.168.50.3/32"

x() { local ns=$1; shift; ip netns exec "$ns" "$@"; }
# nsenter keeps the mount namespace (ip netns exec remounts /sys and would
# hide /sys/fs/bpf).
nx() { local ns=$1; shift; nsenter --net=/run/netns/"$ns" "$@"; }
log() { printf '\n=== %s\n' "$*"; }
bg() { local name=$1 ns=$2; shift 2; setsid nsenter --net=/run/netns/"$ns" "$@" </dev/null >"$W/$name.log" 2>&1 & echo $! >"$W/$name.pid"; }

cleanup() {
	[ "$KEEP" = 1 ] && return 0
	for p in "$W"/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true; done
	pkill -f "$FC" 2>/dev/null || true
	pkill -f "tcpdump -i .* -w $W" 2>/dev/null || true
	for n in na no nt; do $PHANTOM_TEST cleanup -pin "$PIN/$n" >/dev/null 2>&1 || true; done
	"$HERE/topology.sh" down
}
trap cleanup EXIT

rm -rf "$W" && mkdir -p "$W/img"
for n in na no nt; do $PHANTOM_TEST cleanup -pin "$PIN/$n" >/dev/null 2>&1 || true; done
"$HERE/topology.sh" up
"$HERE/topology.sh" offload "$OFFLOAD"

log "start peers and the server in the OLD pod ($OLD)"
bg peer9000 pgr-pa "$PY" "$FC" serve --listen 9000 --report "$W/peer9000.json"
bg ext9100 pgr-ext "$PY" "$FC" serve --listen 9100 --report "$W/ext9100.json"
sleep 0.5
bg server pgr-po "$PY" "$FC" serve --listen 7000 --listen 7001 --listen 7002 --listen 7003 --listen 7004 --listen 7005 --listen-at "$OLD:7006" \
	--dial 10.244.1.10:9000 --dial 192.168.50.100:9100 --report "$W/server.json"
sleep 0.5
bg c1-pod-remote pgr-pa "$PY" "$FC" dial "$OLD:7000" --report "$W/c1.json"
bg c2-host-remote pgr-na "$PY" "$FC" dial "$OLD:7001" --report "$W/c2.json"
bg c3-host-target pgr-nt "$PY" "$FC" dial "$OLD:7002" --report "$W/c3.json"
bg c4-pod-samenode pgr-pt "$PY" "$FC" dial "$OLD:7003" --report "$W/c4.json"
bg c5-clusterip pgr-pa2 "$PY" "$FC" dial "10.96.0.10:80" --report "$W/c5.json"
bg c6-nodeport-ext pgr-ext "$PY" "$FC" dial "192.168.50.1:30080" --report "$W/c6.json"
sleep 2

log "packet captures (wire = router bridge, inside = new pod)"
x pgr-r tcpdump -i br0 -nn -s 128 -w "$W/wire.pcap" tcp 2>/dev/null & echo $! >"$W/tcpdump-wire.pid"
[ "$MODE" = criu ] && { x pgr-pm tcpdump -i eth0 -nn -s 128 -w "$W/inside.pcap" tcp 2>/dev/null & echo $! >"$W/tcpdump-inside.pid"; }
x pgr-pa tcpdump -i eth0 -nn -s 128 -w "$W/peer.pcap" tcp 2>/dev/null & echo $! >"$W/tcpdump-peer.pid"
sleep 1

SPID=$(pgrep -f "$FC serve --listen 7000" | head -1)
T0=$(date +%s.%N)
if [ "$MODE" = criu ]; then
	log "freeze + checkpoint server pid $SPID (criu dump --tcp-established --leave-stopped)"
	nx pgr-po criu dump -t "$SPID" -D "$W/img" --tcp-established --leave-stopped -o dump.log -v2
	PODNS=pgr-pm
else
	log "freeze server pid $SPID (SIGSTOP) and cut the old pod off the old node"
	kill -STOP "$SPID"
	x pgr-no ip link del h-po
	"$HERE/topology.sh" replumb
	"$HERE/topology.sh" offload "$OFFLOAD"
	PODNS=pgr-po
fi
T1=$(date +%s.%N)

log "harvest flows of the frozen pod and resolve NAT with the old node's conntrack"
$PHANTOM_TEST harvest -netns /run/netns/pgr-po -ip "$OLD" -ct-netns /run/netns/pgr-no $NETS >"$W/flows.json"
cat "$W/flows.json"
# Listeners bound to OLD specifically: harvested here, in the frozen old pod.
# With real CRIU the new pod has no sockets until the restore.
OLD_LISTENERS=$($PHANTOM_TEST listeners -netns /run/netns/pgr-po -ip "$OLD")
echo "listeners bound to $OLD: ${OLD_LISTENERS:-none}"
[ "$MODE" = criu ] && kill -9 "$SPID" # network is still locked by CRIU: no FIN/RST leaves

log "program the target node (inbound rules pending), then every peer node"
# Order matters: the target node first (inbound rules pending = drop), then
# the peers. A peer that translates before the target knows the flow makes
# the new pod's kernel answer with RST.
nx pgr-nt $PHANTOM_TEST plan $LEGACY -pin "$PIN/nt" -old "$OLD" -new "$NEW" -flows "$W/flows.json" -target -pending $NORES \
	-pod-netns /run/netns/$PODNS -pod-if eth0 -pod-hostif h-pm \
	-local-pod 10.244.3.30=/run/netns/pgr-pt,eth0,h-pt -host-ip 192.168.50.3 -hostdev uplink -apply
nx pgr-na $PHANTOM_TEST plan $LEGACY $NORES -pin "$PIN/na" -old "$OLD" -new "$NEW" -flows "$W/flows.json" \
	-local-pod 10.244.1.10=/run/netns/pgr-pa,eth0,h-pa -local-pod 10.244.1.11=/run/netns/pgr-pa2,eth0,h-pa2 \
	-host-ip 192.168.50.1 -hostdev uplink -via-netfilter 10.244.1.11 -apply
# Self-IP fix-up in the new pod (listener bound to OLD:7006, see docs 9).
nx pgr-nt $PHANTOM_TEST selfip -netns /run/netns/$PODNS -old "$OLD" -new "$NEW" ${OLD_LISTENERS:+-ports "$OLD_LISTENERS"}
T2=$(date +%s.%N)
[ "$MODE" = replumb ] && { x pgr-po tcpdump -i eth0 -nn -s 128 -w "$W/inside.pcap" tcp 2>/dev/null & echo $! >"$W/tcpdump-inside.pid"; sleep 0.3; }

if [ "$MODE" = criu ]; then
	log "old pod deleted"
	ip netns del pgr-po
	log "restore in the NEW pod ($NEW, $OLD on lo)"
	nx pgr-pm criu restore -D "$W/img" --tcp-established -d -o restore.log -v2
else
	log "resume the server (its namespace is now the NEW pod)"
	kill -CONT "$SPID"
fi
T3=$(date +%s.%N)
nx pgr-nt $PHANTOM_TEST clear-pending -pin "$PIN/nt"
T4=$(date +%s.%N)
awk -v a="$T0" -v b="$T1" -v c="$T2" -v d="$T3" -v e="$T4" 'BEGIN{printf "dump %.0f ms, harvest+program %.0f ms, restore %.0f ms, clear-pending %.1f ms\n",(b-a)*1000,(c-b)*1000,(d-c)*1000,(e-d)*1000}'

sleep 6
for p in "$W"/tcpdump-*.pid; do kill "$(cat "$p")" 2>/dev/null || true; done
sleep 0.5

log "results"
set +e # analysis only from here on; failures are collected in $fail
fail=0
snap() { "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sum(s["received"] for s in d.values()))' "$1"; }
FILES="c1 c2 c3 c4 c5 c6 peer9000 ext9100"
for c in $FILES; do eval "before_$c=$(snap "$W/$c.json")"; done
sleep 2
check() { # id description expect(ok|broken)
	local c=$1 name=$2 want=$3 b a r got
	b=$(eval echo \$before_$c); a=$(snap "$W/$c.json")
	r=$("$PY" - "$W/$c.json" "$((a - b))" <<'EOF2'
import json, sys
d = json.load(open(sys.argv[1]))
progress = int(sys.argv[2])
bad = progress <= 0
for k, s in d.items():
    bad |= bool(s["errors"]) or s["closed"] or s["gaps"] != 0
    print("  %-28s recv=%-6d gaps=%d max_gap=%.0fms errors=%s closed=%s" % (k, s["received"], s["gaps"], s["max_gap_ms"], s["errors"], s["closed"]))
print("  progress in the last 2 s: %d messages" % progress)
print("RESULT", "broken" if bad else "ok")
EOF2
)
	echo "$name (expect $want):"
	echo "$r" | grep -v RESULT
	got=$(echo "$r" | awk '/RESULT/{print $2}')
	if [ "$got" != "$want" ]; then echo "  -> UNEXPECTED ($got)"; fail=1; fi
}
check c1 "c1 pod->pod, other node" ok
check c2 "c2 host netns, other node" ok
check c3 "c3 host netns, target node" ok
check c4 "c4 pod->pod, same node as new pod" ok
check c5 "c5 pod->ClusterIP (kube-proxy DNAT)" ok
check c6 "c6 outside->NodePort (DNAT+SNAT)" ok
check peer9000 "c7 migrated pod -> in-cluster peer" ok
check ext9100 "c8 migrated pod -> outside via old-node SNAT (unsupported by plain Phantom mode)" broken
log "new connections that would collide with migrated wire tuples (reservation)"
P1=$("$PY" -c 'import json,sys; print([f["Remote"] for f in json.load(open(sys.argv[1])) if f["Local"].endswith(":7000")][0].split(":")[1])' "$W/flows.json")
P6=$("$PY" -c 'import json,sys; print([f["Remote"] for f in json.load(open(sys.argv[1])) if f["Local"].endswith(":7005")][0].split(":")[1])' "$W/flows.json")
echo "reserved in pgr-pa: $(x pgr-pa cat /proc/sys/net/ipv4/ip_local_reserved_ports)  (c1 uses $P1)"
# (a) Peer pod: its ephemeral range only offers c1's port and the next one.
x pgr-pa sysctl -qw net.ipv4.ip_local_port_range="$P1 $((P1 + 1))"
bg n1 pgr-pa "$PY" "$FC" dial "$NEW:7000" --report "$W/n1.json"
# (c) New connection to NEW for a listener the app bound to OLD (self-IP fix-up).
bg n7 pgr-pt "$PY" "$FC" dial "$NEW:7006" --report "$W/n7.json"
# (b) NodePort: kube-proxy now sends new connections to NEW; a second
# outside client uses the same source port as c6, so masquerade would like
# to reuse c6's SNAT port on node A.
x pgr-na iptables-legacy -t nat -I PREROUTING 1 -d 192.168.50.1 -p tcp --dport 30080 -j DNAT --to-destination "$NEW:7005"
x pgr-na iptables-legacy -t nat -A POSTROUTING -s 192.168.50.0/24 -d "$NEW" -p tcp --dport 7005 -j MASQUERADE
x pgr-ext ip addr add 192.168.50.101/24 dev uplink
bg n6 pgr-ext "$PY" "$FC" dial "192.168.50.1:30080" --bind 192.168.50.101 --sport "$P6" --report "$W/n6.json"
sleep 3
for c in c1 c6 n1 n6 n7; do eval "before_$c=$(snap "$W/$c.json")"; done
sleep 2
check c1 "c1 still alive next to a new connection from the same pod" ok
check n1 "n1 new pod->NEW connection (must not take c1's port $P1)" ok
check c6 "c6 still alive next to a new NodePort connection" ok
check n6 "n6 new outside->NodePort connection, same client port $P6" ok
check n7 "n7 new connection to NEW:7006, app listener bound to OLD (self-IP fix-up)" ok
"$PY" -c 'import json,sys; [print("  n1 local port:", s["local"]) for s in json.load(open(sys.argv[1])).values()]' "$W/n1.json"
echo "  server sees the NodePort connections from:"; "$PY" -c 'import json,sys; [print("   ", k, s["peer"]) for k,s in json.load(open(sys.argv[1])).items() if k.startswith("in:7005")]' "$W/server.json"

log "IP reuse: a NEW pod on the old node gets OLD while the rules are active"
x pgr-no ip link show h-po2 >/dev/null 2>&1 || {
	ip netns add pgr-po2
	ip -n pgr-no link add h-po2 type veth peer name eth0 netns pgr-po2
	x pgr-no ip link set h-po2 up
	x pgr-no sysctl -qw net.ipv4.conf.h-po2.proxy_arp=1
	x pgr-no ip route replace "$OLD/32" dev h-po2
	x pgr-po2 ip link set lo up
	x pgr-po2 ip addr add "$OLD/32" dev eth0
	x pgr-po2 ip link set eth0 up
	x pgr-po2 ip route add 169.254.1.1 dev eth0 scope link
	x pgr-po2 ip route add default via 169.254.1.1 dev eth0 onlink
}
x pgr-pa sysctl -qw net.ipv4.ip_local_port_range="32768 60999"
bg reuse-srv pgr-po2 "$PY" "$FC" serve --listen 7000 --report "$W/reuse-srv.json"
sleep 0.5
bg reusecli pgr-pa "$PY" "$FC" dial "$OLD:7000" --report "$W/reusecli.json"
sleep 2
for c in c1 reusecli; do eval "before_$c=$(snap "$W/$c.json")"; done
sleep 2
check c1 "c1 (migrated, translated to NEW) next to the recycled OLD" ok
check reusecli "new connection to OLD reaches the recycled OLD's new owner (untranslated)" ok
"$PY" -c 'import json,sys; [print("  new connection to the recycled OLD served by:", s["local"], "recv", s["received"]) for s in json.load(open(sys.argv[1])).values()]' "$W/reuse-srv.json"
[ -s "$W/reuse-srv.json" ] && grep -q received "$W/reuse-srv.json" || { echo "  -> UNEXPECTED: new owner of OLD not reached"; fail=1; }

log "remove the mapping and detach (twice: idempotent)"
for n in na nt; do
	ID=$(nx pgr-$n $PHANTOM_TEST rules -pin "$PIN/$n" | awk -F'owner=' 'NF>1{split($2,a," "); print a[1]; exit}')
	[ -n "$ID" ] && nx pgr-$n $PHANTOM_TEST remove -pin "$PIN/$n" -id "$ID"
done
for n in na nt; do echo "  rules left on $n: $(nx pgr-$n $PHANTOM_TEST rules -pin "$PIN/$n" | grep -c .)"; done
for round in 1 2; do
	for n in na nt; do nx pgr-$n $PHANTOM_TEST cleanup -pin "$PIN/$n" || { echo "cleanup $n round $round failed"; fail=1; }; done
done
left=0
for ns in pgr-pa pgr-pa2 pgr-pt pgr-na pgr-nt $PODNS; do
	for d in $(ip -n $ns -o link 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
		n=$( (ip netns exec $ns tc filter show dev "$d" ingress; ip netns exec $ns tc filter show dev "$d" egress) 2>/dev/null | grep -c paguro || true)
		m=$(nsenter --net=/run/netns/$ns bpftool net show dev "$d" 2>/dev/null | grep -c xl_ || true)
		left=$((left + n + m))
	done
done
echo "  programs still attached anywhere: $left"
[ "$left" = 0 ] || fail=1
eval "before_reusecli=$(snap "$W/reusecli.json")"; sleep 2
check reusecli "connection to the recycled OLD keeps working after removal/detach" ok

echo "restored server view:"; "$PY" -c 'import json,sys; [print("  %-22s recv=%d gaps=%d errors=%s" % (k,s["received"],s["gaps"],s["errors"])) for k,s in json.load(open(sys.argv[1])).items()]' "$W/server.json"

log "checksums (tcpdump -vv): incorrect checksums on wire / inside / peer"
for f in wire inside peer; do
	n=$(tcpdump -nn -vv -r "$W/$f.pcap" 2>/dev/null | grep -c incorrect || true)
	t=$(tcpdump -nn -r "$W/$f.pcap" 2>/dev/null | wc -l)
	echo "  $f: $n incorrect of $t packets"
	if [ "$OFFLOAD" = off ] && [ "$n" != 0 ]; then fail=1; fi
done
log "addresses on the wire after the migration (expect $NEW, never $OLD for translated flows)"
tcpdump -nn -r "$W/wire.pcap" 2>/dev/null | awk '{print $3" > "$5}' | sed -E 's/\.[0-9]+( |:|$)/\1/g' | sort | uniq -c | sort -rn | head -20
echo "inside the new pod:"
tcpdump -nn -r "$W/inside.pcap" 2>/dev/null | awk '{print $3" > "$5}' | sed -E 's/\.[0-9]+( |:|$)/\1/g' | sort | uniq -c | sort -rn | head -10
echo "kernel checksum errors (TcpInCsumErrors) in new pod / peer:"
for n in $PODNS pgr-pa; do x $n nstat -az TcpInCsumErrors | awk -v n=$n '/TcpInCsumErrors/{print "  "n": "$2}'; done

for n in na nt; do echo "node $n stats:"; $PHANTOM_TEST stats -pin "$PIN/$n" | tr -d '\n ' ; echo; done

[ "$fail" = 0 ] && log "PASS" || { log "FAIL"; exit 1; }
