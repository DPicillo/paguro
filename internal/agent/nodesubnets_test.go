// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import "testing"

func TestSubnetOf(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.78.222/19": "192.168.64.0/19", // an EKS node's ENI
		"10.42.0.89/24":     "10.42.0.0/24",
		"127.0.0.1/8":       "",
		"169.254.1.1/16":    "",
		"192.168.74.81/32":  "", // a host route, not a subnet
		"garbage":           "",
	} {
		if got := subnetOf(in); got != want {
			t.Errorf("subnetOf(%q) = %q, want %q", in, got, want)
		}
	}
}
