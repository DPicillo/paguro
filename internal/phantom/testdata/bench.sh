#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Per-packet overhead of the Phantom-mode datapath, end to end.
#
#   peer (10.251.1.10) -- router -- pod (eth0 NEW 10.251.3.20, lo OLD 10.251.2.10)
#
# Scenarios:
#   baseline      no programs, traffic to NEW
#   attached      programs on both pod interfaces + 100k unrelated rules,
#                 traffic to NEW (cost for traffic that is not translated)
#   translated    traffic to OLD, every flow translated on both ends
#
# iperf3 (single TCP stream, 5 s, median of 3) and netperf TCP_RR (1 byte
# request/response, 5 s, median of 3).
#
#   sudo PHANTOM_TEST=/path/paguro-phantom-test bench.sh
set -euo pipefail
PHANTOM_TEST=${PHANTOM_TEST:-paguro-phantom-test}
PIN=/sys/fs/bpf/pgr-bench
OLD=10.251.2.10
NEW=10.251.3.20
x() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

down() { for n in pgrb-peer pgrb-pod pgrb-r; do ip netns del $n 2>/dev/null || true; done; $PHANTOM_TEST cleanup -pin $PIN >/dev/null 2>&1 || true; }
[ "${KEEP:-0}" = 1 ] || trap 'pkill -f "iperf3 -s -B 0.0.0.0 -p 5201" 2>/dev/null; pkill -x netserver 2>/dev/null; down' EXIT
down
for n in pgrb-peer pgrb-pod pgrb-r; do ip netns add $n; x $n ip link set lo up; done
ip -n pgrb-peer link add eth0 type veth peer name vpeer netns pgrb-r
ip -n pgrb-pod link add eth0 type veth peer name vpod netns pgrb-r
x pgrb-r sysctl -qw net.ipv4.ip_forward=1
x pgrb-r ip addr add 10.251.1.1/24 dev vpeer
x pgrb-r ip addr add 10.251.3.1/24 dev vpod
x pgrb-r ip link set vpeer up
x pgrb-r ip link set vpod up
x pgrb-peer ip addr add 10.251.1.10/24 dev eth0
x pgrb-peer ip link set eth0 up
x pgrb-peer ip route add default via 10.251.1.1
x pgrb-pod ip addr add $NEW/24 dev eth0
x pgrb-pod ip addr add $OLD/32 dev lo
x pgrb-pod sysctl -qw net.ipv4.conf.all.arp_announce=2
x pgrb-pod ip link set eth0 up
x pgrb-pod ip route add default via 10.251.3.1
# Known client ports so the translated flows can be registered up front.
x pgrb-peer sysctl -qw net.ipv4.tcp_tw_reuse=1
# Translated runs use 45000-45199 (registered flows), the others 46100-46299:
# a new connection to NEW must never reuse a migrated flow's wire tuple (in
# production the reservation guarantees that; the benchmark separates the
# ranges itself and therefore runs without reservations).
prange() { x pgrb-peer sysctl -qw net.ipv4.ip_local_port_range="$1 $2"; }

taskset -c 3 ip netns exec pgrb-pod iperf3 -s -B 0.0.0.0 -p 5201 -D
taskset -c 3 ip netns exec pgrb-pod netserver -p 12865 >/dev/null

median() { sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
tput() { x pgrb-peer taskset -c 2 iperf3 -c "$1" -p 5201 -t 3 -J | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["end"]["sum_received"]["bits_per_second"]/1e9 if "sum_received" in d["end"] else sys.exit("iperf3: %s" % d.get("error")))'; }
# rr TARGET LOCALDATAPORT: the translated run uses the registered port 46000,
# the others 46500 (see the port range comment above).
rr() { x pgrb-peer taskset -c 2 netperf -H "$1" -p 12865 -t TCP_RR -l 3 -P 0 -- -r 1,1 -P "$2",7777 | awk 'NF>=6{print $6}' | tail -1; }
attach() { for n in pgrb-peer pgrb-pod; do $PHANTOM_TEST $1 -pin $PIN -kind pod -netns /run/netns/$n -if eth0; done; }

# 100k unrelated rules + the rules of the translated flows (control and
# data connections of both tools; the peer's ephemeral range is pinned).
python3 - >/tmp/pgrb-flows.json <<'PY'
import json
fl = [{"Proto": 6, "Local": "10.251.2.10:%d" % (1000 + i % 60000), "Remote": "10.99.%d.%d:%d" % (i >> 8 & 255, i & 255, 20000 + i // 65536)} for i in range(100000)]
for sp in list(range(45000, 45200)) + [46000]:
    for dp in (5201, 12865, 7777):
        fl.append({"Proto": 6, "Local": "10.251.2.10:%d" % dp, "Remote": "10.251.1.10:%d" % sp})
print(json.dumps(fl))
PY
$PHANTOM_TEST plan -pin $PIN -old $OLD -new $NEW -flows /tmp/pgrb-flows.json -target -pod-netns /run/netns/pgrb-pod -no-reservations -apply >/dev/null
$PHANTOM_TEST plan -pin $PIN -old $OLD -new $NEW -flows /tmp/pgrb-flows.json -local-pod 10.251.1.10=/run/netns/pgrb-peer,eth0 -no-reservations -apply >/dev/null
echo "rules installed: $($PHANTOM_TEST rules -pin $PIN | wc -l)"

ROUNDS=${ROUNDS:-5}
: >/tmp/pgrb-res
for r in $(seq 1 "$ROUNDS"); do
	attach detach
	prange 46100 46299
	echo "baseline $(tput $NEW) $(rr $NEW 46500)" >>/tmp/pgrb-res
	attach attach
	echo "attached $(tput $NEW) $(rr $NEW 46500)" >>/tmp/pgrb-res
	prange 45000 45199
	echo "translated $(tput $OLD) $(rr $OLD 46000)" >>/tmp/pgrb-res
done
echo "median of $ROUNDS interleaved rounds (iperf3 3 s single stream, netperf TCP_RR 3 s, 1-byte):"
for s in baseline attached translated; do
	t=$(awk -v s=$s '$1==s{print $2}' /tmp/pgrb-res | median)
	q=$(awk -v s=$s '$1==s{print $3}' /tmp/pgrb-res | median)
	awk -v l="$s" -v t="$t" -v r="$q" 'BEGIN{printf "  %-11s %6.2f Gbit/s   %8.0f trans/s  (%.2f us per round trip)\n", l, t, r, 1000000/r}'
done
echo "raw:"; sed 's/^/  /' /tmp/pgrb-res
$PHANTOM_TEST stats -pin $PIN | tr -d ' \n'; echo
