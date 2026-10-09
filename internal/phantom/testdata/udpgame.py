#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""A UDP game server and player for the Phantom-mode tests (udp-rebind.sh).

The server behaves like Xonotic/DarkPlaces or a RakNet server: one
unconnected socket for all players, each player known by the address its
datagrams come from. A player joins once ("J <id>"), then sends input every
--interval seconds ("I <id> <seq>"). The server answers the input of a known
address and sends a state update to every known player at 20 Hz on its
own; input from an unknown address is ignored (a stranger) and counted.

  udpgame.py serve --port 26000 --report /tmp/srv.json
  udpgame.py play 192.168.50.1:30260 --id 1 --report /tmp/p1.json

Server report: per player id the address it joined from, inputs answered,
and strangers (other addresses that sent this id's input).
Player report: replies received, the largest gap between two replies
(max_gap_ms), and timed_out (a gap longer than --timeout seconds).
"""
import argparse
import json
import socket
import threading
import time

lock = threading.Lock()


def write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
    import os
    os.replace(tmp, path)


def serve(args):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", args.port))
    players = {}  # addr -> id
    report = {}  # id -> {"addr", "inputs", "strangers": {addr: n}}

    def ticker():
        while True:
            time.sleep(0.05)
            with lock:
                known = list(players.items())
            for addr, pid in known:
                try:
                    s.sendto(b"S tick", addr)
                except OSError:
                    pass

    def reporter():
        while True:
            time.sleep(0.2)
            with lock:
                write(args.report, report)

    threading.Thread(target=ticker, daemon=True).start()
    threading.Thread(target=reporter, daemon=True).start()
    while True:
        data, addr = s.recvfrom(2048)
        parts = data.decode(errors="replace").split()
        if len(parts) < 2:
            continue
        kind, pid = parts[0], parts[1]
        with lock:
            if kind == "J" and addr not in players:
                players[addr] = pid
                report.setdefault(pid, {"addr": "%s:%d" % addr, "inputs": 0, "strangers": {}})
            elif kind == "I":
                if players.get(addr) == pid:
                    report[pid]["inputs"] += 1
                    try:
                        s.sendto(("S %s" % parts[2]).encode(), addr)
                    except OSError:
                        pass  # e.g. EPERM from the restore's hold, as a real server ignores it
                elif pid in report:
                    k = "%s:%d" % addr
                    report[pid]["strangers"][k] = report[pid]["strangers"].get(k, 0) + 1


def play(args):
    host, port = args.target.rsplit(":", 1)
    dst = (host, int(port))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.05)
    st = {"received": 0, "max_gap_ms": 0.0, "timed_out": False, "sent": 0, "local": None}
    last = [None]

    def sender():
        s.sendto(("J %s" % args.id).encode(), dst)
        seq = 0
        while True:
            time.sleep(args.interval)
            seq += 1
            try:
                s.sendto(("I %s %d" % (args.id, seq)).encode(), dst)
                with lock:
                    st["sent"] = seq
            except OSError:
                pass

    threading.Thread(target=sender, daemon=True).start()
    next_report = 0.0
    while True:
        try:
            data, _ = s.recvfrom(2048)
            now = time.monotonic()
            with lock:
                st["received"] += 1
                if st["local"] is None:
                    st["local"] = "%s:%d" % s.getsockname()
                if last[0] is not None:
                    gap = (now - last[0]) * 1000
                    st["max_gap_ms"] = max(st["max_gap_ms"], gap)
                    if gap > args.timeout * 1000:
                        st["timed_out"] = True
                last[0] = now
        except socket.timeout:
            pass
        now = time.monotonic()
        if last[0] is not None and now - last[0] > args.timeout:
            with lock:
                st["timed_out"] = True
        if now >= next_report:
            next_report = now + 0.2
            with lock:
                write(args.report, st)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("serve")
    a.add_argument("--port", type=int, default=26000)
    a.add_argument("--report", required=True)
    b = sub.add_parser("play")
    b.add_argument("target")
    b.add_argument("--id", default="1")
    b.add_argument("--interval", type=float, default=0.033)
    b.add_argument("--timeout", type=float, default=5.0)
    b.add_argument("--report", required=True)
    args = ap.parse_args()
    serve(args) if args.cmd == "serve" else play(args)


if __name__ == "__main__":
    main()
