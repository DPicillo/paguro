// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package images

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestPinned(t *testing.T) {
	const d = "sha256:0687a6bc9716edc2a6ee0fbfb0f87e7ee358b262b67c9215de91bc9b2d38ba71"
	for _, c := range []struct{ image, imageID, want string }{
		{"python:3.12-alpine", "docker.io/library/python@" + d, "python@" + d},
		{"registry.example.com:5000/demo-app:v6", "registry.example.com:5000/demo-app@" + d, "registry.example.com:5000/demo-app@" + d},
		{"registry.example.com:5000/demo-app", "registry.example.com:5000/demo-app@" + d, "registry.example.com:5000/demo-app@" + d},
		{"busybox", "docker.io/library/busybox@" + d, "busybox@" + d},
		// already pinned: unchanged
		{"busybox@sha256:1111", "docker.io/library/busybox@" + d, "busybox@sha256:1111"},
		// imported locally, no repository digest: cannot be pulled by ID
		{"app:dev", d, "app:dev"},
		{"app:dev", "", "app:dev"},
	} {
		if got := Pinned(c.image, c.imageID); got != c.want {
			t.Errorf("Pinned(%q, %q) = %q, want %q", c.image, c.imageID, got, c.want)
		}
	}
}

func TestForPod(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "proxy", Image: "envoy:v1"}, {Name: "setup", Image: "busybox"}},
			Containers:     []corev1.Container{{Name: "app", Image: "python:3.12-alpine"}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses:     []corev1.ContainerStatus{{Name: "app", ImageID: "docker.io/library/python@sha256:aa"}},
			InitContainerStatuses: []corev1.ContainerStatus{{Name: "proxy", ImageID: "docker.io/library/envoy@sha256:bb"}, {Name: "setup"}},
		},
	}
	got := ForPod(pod)
	if got["app"] != "python@sha256:aa" || got["proxy"] != "envoy@sha256:bb" || len(got) != 2 {
		t.Fatalf("ForPod = %v", got)
	}
}
