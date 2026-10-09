// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package images pins a migrated pod's images to exactly what the source
// node ran.
//
// A tag can point to different images on different nodes: one node pulled
// it a week ago, the target pulls it now. A restored process would then run
// with other files below it than it was started with – CRIU refuses that
// for mapped libraries (measured: "File usr/local/lib/libpython3.12.so.1.0
// has bad build-ID" → cold start, memory state lost), and the rootfs delta
// the source sends would land on another base. The container status names
// the image the node actually runs (imageID, a repository digest); the
// replacement and the target's pre-pull use it.
package images

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Pinned returns image pinned to the digest of imageID (from the container
// status), e.g. "python:3.12-alpine" + "docker.io/library/python@sha256:ab…"
// → "python@sha256:ab…". It returns image unchanged when it already carries a
// digest or when imageID is not a repository digest (an image imported
// locally has only its config ID, "sha256:…", which cannot be pulled).
func Pinned(image, imageID string) string {
	_, digest, ok := strings.Cut(imageID, "@")
	if !ok || !strings.HasPrefix(digest, "sha256:") || strings.Contains(image, "@") || image == "" {
		return image
	}
	return Repository(image) + "@" + digest
}

// Repository strips the tag from an image reference. A ':' only starts a
// tag after the last '/' (a registry may carry a port: host:5000/app:v1).
func Repository(image string) string {
	if i := strings.LastIndexByte(image, ':'); i > strings.LastIndexByte(image, '/') {
		return image[:i]
	}
	return image
}

// ForPod maps container names to their pinned images, for the containers
// and init containers (sidecars) the pod's status reports.
func ForPod(pod *corev1.Pod) map[string]string {
	spec := map[string]string{}
	for _, c := range pod.Spec.Containers {
		spec[c.Name] = c.Image
	}
	for _, c := range pod.Spec.InitContainers {
		spec[c.Name] = c.Image
	}
	out := map[string]string{}
	for _, list := range [][]corev1.ContainerStatus{pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses} {
		for _, s := range list {
			if img, ok := spec[s.Name]; ok && s.ImageID != "" {
				out[s.Name] = Pinned(img, s.ImageID)
			}
		}
	}
	return out
}
