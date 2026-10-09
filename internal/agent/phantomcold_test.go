// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"net/netip"
	"slices"
	"testing"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/phantom"
)

// After a cold start of the replacement, a node aborts its own ends of the
// dead connections: a peer pod's socket, a host socket, a pod's socket to a
// ClusterIP (its own tuple from conntrack) – not the migrated pod's side,
// not peers outside the cluster, not UDP, not twice.
func TestStrandedSockets(t *testing.T) {
	ap := netip.MustParseAddrPort
	old, new := netip.MustParseAddr("192.168.93.41"), netip.MustParseAddr("192.168.90.95")
	nodeIP := netip.MustParseAddr("192.168.78.222")
	srv := netip.AddrPortFrom(old, 25565)
	flows := []phantom.Flow{
		{Proto: phantom.TCP, Local: srv, Remote: ap("10.244.1.10:40000"), Server: true},    // peer pod, direct
		{Proto: phantom.TCP, Local: srv, Remote: ap("10.244.1.11:40001"), Server: true},    // pod behind a ClusterIP
		{Proto: phantom.TCP, Local: srv, Remote: ap("192.168.78.222:51000"), Server: true}, // NodePort client, masqueraded
		{Proto: phantom.TCP, Local: srv, Remote: ap("192.168.78.222:40002"), Server: true}, // host socket
		{Proto: phantom.UDP, Local: srv, Remote: ap("10.244.1.10:5000"), Server: true},     // UDP
		{Proto: phantom.TCP, Local: srv, Remote: ap("10.244.1.10:40003"), Server: true},    // aborted before
	}
	viaNAT := map[netip.AddrPort]bool{ap("10.244.1.11:40001"): true}
	nc := phantom.NodeContext{
		IsTarget: true, Migrated: phantom.PodEndpoint{Netns: "/run/netns/migrated", Ifname: "eth0"},
		HostIPs: map[netip.Addr]bool{nodeIP: true},
		LocalPods: map[netip.Addr]phantom.PodEndpoint{
			netip.MustParseAddr("10.244.1.10"): {Netns: "/proc/77/ns/net", Ifname: "eth0"},
			netip.MustParseAddr("10.244.1.11"): {Netns: "/proc/88/ns/net", Ifname: "eth0"},
		},
		ViaNetfilter: func(f phantom.Flow) bool { return viaNAT[f.Remote] },
		HostDevices:  []string{"ens5"},
	}
	plans, err := phantom.PlanFlows(phantom.Migration{ID: 7, OldIP: old, NewIP: new}, flows, nc)
	if err != nil {
		t.Fatal(err)
	}
	r := &phantomRecord{Target: true, Netns: "/run/netns/migrated", PerFlow: plans, Aborted: []int32{5}}
	orig := map[phantom.Tuple]phantom.Tuple{
		{Proto: phantom.TCP, Src: ap("10.244.1.11:40001"), Dst: srv}:    {Proto: phantom.TCP, Src: ap("10.244.1.11:40001"), Dst: ap("10.96.0.10:80")},
		{Proto: phantom.TCP, Src: ap("192.168.78.222:51000"), Dst: srv}: {Proto: phantom.TCP, Src: ap("203.0.113.7:61000"), Dst: ap("192.168.78.222:30717")},
	}
	podNetns := map[netip.Addr]string{
		netip.MustParseAddr("10.244.1.10"): "/proc/77/ns/net",
		netip.MustParseAddr("10.244.1.11"): "/proc/88/ns/net",
	}
	got := strandedSockets(r, flows, []int32{0, 1, 2, 3, 4, 5}, orig, nc.HostIPs, podNetns)
	want := []strandedSocket{
		{Netns: "/proc/77/ns/net", Local: ap("10.244.1.10:40000"), Remote: srv},
		{Netns: "/proc/88/ns/net", Local: ap("10.244.1.11:40001"), Remote: ap("10.96.0.10:80")},
		{Netns: "", Local: ap("192.168.78.222:40002"), Remote: srv},
	}
	if !slices.Equal(got, want) {
		t.Errorf("stranded sockets\n got %+v\nwant %+v", got, want)
	}
	if got := strandedSockets(r, flows, []int32{0}, orig, nc.HostIPs, podNetns); len(got) != 1 {
		t.Errorf("only the dead flows: %+v", got)
	}
}

func TestColdStarted(t *testing.T) {
	m := &v1.Migration{}
	m.Status.Target.Containers = []v1.TargetContainerStatus{{Name: "app", Restored: true}}
	if coldStarted(m) {
		t.Error("restored counts as cold-started")
	}
	m.Status.Target.Containers = append(m.Status.Target.Containers, v1.TargetContainerStatus{Name: "side", ColdStartReason: "restore failed"})
	if !coldStarted(m) {
		t.Error("a cold-started container does not count")
	}
}
