#!/usr/bin/env python3
"""Long-lived TCP stream checker for the Phantom-mode tests.

Every connection carries a symmetric stream: each side sends an 8-byte
big-endian sequence number every --interval seconds and verifies that the
numbers it receives are strictly consecutive. A report (JSON, one object per
connection) is rewritten to --report every 200 ms, so it survives a CRIU
checkpoint/restore of the process.

  flowcheck.py serve --listen 7000 --listen 7001 [--dial 10.0.0.1:9000] --report /tmp/srv.json
  flowcheck.py dial 10.244.2.10:7000 --report /tmp/cli.json [--bind IP]

Report fields: received, expected_next, gaps (number of discontinuities),
max_gap_ms (largest inter-arrival time), errors, closed.
"""
import argparse
import json
import socket
import struct
import threading
import time

lock = threading.Lock()
conns = {}


def stream(name, sock, interval):
    st = {"received": 0, "expected_next": 0, "gaps": 0, "max_gap_ms": 0.0,
          "errors": [], "closed": False, "sent": 0,
          "local": "%s:%d" % sock.getsockname()[:2], "peer": "%s:%d" % sock.getpeername()[:2]}
    with lock:
        conns[name] = st
    stop = threading.Event()

    def sender():
        seq = 0
        try:
            while not stop.is_set():
                sock.sendall(struct.pack("!Q", seq))
                seq += 1
                st["sent"] = seq
                time.sleep(interval)
        except OSError as e:
            st["errors"].append("send: %s" % e)
            stop.set()

    threading.Thread(target=sender, daemon=True).start()
    buf = b""
    last = None
    try:
        while True:
            data = sock.recv(65536)
            if not data:
                st["closed"] = True
                break
            now = time.monotonic()
            if last is not None:
                st["max_gap_ms"] = max(st["max_gap_ms"], (now - last) * 1000)
            last = now
            buf += data
            while len(buf) >= 8:
                (seq,) = struct.unpack("!Q", buf[:8])
                buf = buf[8:]
                if seq != st["expected_next"]:
                    st["gaps"] += 1
                st["expected_next"] = seq + 1
                st["received"] += 1
    except OSError as e:
        st["errors"].append("recv: %s" % e)
    stop.set()


def reporter(path):
    while True:
        with lock:
            snap = json.dumps(conns, indent=1)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(snap)
        import os
        os.replace(tmp, path)
        time.sleep(0.2)


def serve(args):
    specs = [("0.0.0.0", p) for p in args.listen]
    for spec in args.listen_at or []:
        host, port = spec.rsplit(":", 1)
        specs.append((host, int(port)))
    for addr, p in specs:
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((addr, p))
        ls.listen(16)

        def acceptor(ls=ls, p=p):
            n = 0
            while True:
                c, _ = ls.accept()
                n += 1
                threading.Thread(target=stream, args=("in:%d#%d" % (p, n), c, args.interval), daemon=True).start()

        threading.Thread(target=acceptor, daemon=True).start()
    for d in args.dial or []:
        host, port = d.rsplit(":", 1)
        c = socket.create_connection((host, int(port)))
        threading.Thread(target=stream, args=("out:%s" % d, c, args.interval), daemon=True).start()
    reporter(args.report)


def dial(args):
    host, port = args.target.rsplit(":", 1)
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if args.bind or args.sport:
        c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        c.bind((args.bind or "0.0.0.0", args.sport))
    c.connect((host, int(port)))
    threading.Thread(target=stream, args=("dial:%s" % args.target, c, args.interval), daemon=True).start()
    reporter(args.report)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--listen", type=int, action="append", default=[])
    s.add_argument("--listen-at", action="append", help="IP:PORT, listener bound to a specific address")
    s.add_argument("--dial", action="append")
    s.add_argument("--report", required=True)
    s.add_argument("--interval", type=float, default=0.002)
    d = sub.add_parser("dial")
    d.add_argument("target")
    d.add_argument("--report", required=True)
    d.add_argument("--bind")
    d.add_argument("--sport", type=int, default=0)
    d.add_argument("--interval", type=float, default=0.002)
    a = ap.parse_args()
    serve(a) if a.cmd == "serve" else dial(a)


if __name__ == "__main__":
    main()
