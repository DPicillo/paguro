#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 David Picillo
#
# The installer picks the containerd it prepares from /proc and runs
# programs from that process's PATH, config and binary as root. Pods share
# the PID view (hostPID) and may name a process "containerd": only a system
# service that sees the host's root may be picked. Runs install.sh's
# functions against fake /proc trees (no node, no root needed).
#
#   build/node-installer/test-discovery.sh        (make installer-unit)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0

# proc <dir> <pid> <comm> <cgroup> <root>
proc() {
	mkdir -p "$1/$2"
	echo "$3" > "$1/$2/comm"
	echo "0::$4" > "$1/$2/cgroup"
	ln -s "$5" "$1/$2/root"
	printf 'PATH=/usr/bin\0' > "$1/$2/environ"
}
mkdir -p "$work/podroot"
expect() { # name proc-dir want
	local got
	got=$(PAGURO_INSTALLER_LIB=1 PAGURO_PROC="$2" bash -c 'source "$0" install >/dev/null; find_containerd_pid || echo none' "$here/install.sh")
	if [ "$got" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1: got $got, want $3"; fails=1; fi
}

p=$work/k3s
proc "$p" 1 systemd /init.scope /
proc "$p" 10 containerd /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1.slice/cri-containerd-a.scope "$work/podroot"
proc "$p" 11 containerd /kubepods.slice/kubepods-pod2.slice/cri-containerd-b.scope/system.slice/containerd.service /
proc "$p" 12 containerd /system.slice/evil.service "$work/podroot"
proc "$p" 100 containerd /system.slice/k3s.service /
expect "k3s: the service's containerd, not the pods' look-alikes" "$p" 100

p=$work/bottlerocket
proc "$p" 1 systemd /init.scope /
proc "$p" 1200 containerd /system.slice/host-containerd.service /
proc "$p" 1300 containerd /runtime.slice/containerd.service /
expect "Bottlerocket: containerd.service before host-containerd" "$p" 1300

p=$work/pods-only
proc "$p" 1 systemd /init.scope /
proc "$p" 10 containerd /kubepods.slice/kubepods-pod1.slice/cri-containerd-a.scope "$work/podroot"
proc "$p" 11 containerd /system.slice/evil.service "$work/podroot"
expect "only look-alikes: none" "$p" none

exit $fails
