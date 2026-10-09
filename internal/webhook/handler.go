// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-logr/logr"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
)

// Path the webhook is served under (must match the
// MutatingWebhookConfiguration).
const PodMutatePath = "/mutate-v1-pod"

// stickyBudget bounds the sticky IP allocation. The API server gives the
// webhook 5 s and then admits the pod unmutated (failurePolicy Ignore); a
// pod that at least gets the RuntimeClass stays migratable without a
// sticky IP.
var stickyBudget = 3 * time.Second

// IPAllocator allocates sticky IPs (implemented by netadapter.StickyAllocator).
type IPAllocator interface {
	Allocate(ctx context.Context) (poolName string, ip netip.Addr, err error)
}

// PodMutator is the admission handler for Pod CREATE.
type PodMutator struct {
	Registry Interceptor
	// ClusterAdapter returns the cluster's detected CNI adapter.
	ClusterAdapter func() netadapter.Adapter
	// Sticky is nil when no sticky IPs are allocated (not Cilium).
	Sticky IPAllocator
	// CPUBaseline returns the CPU features a new migratable pod's runtimes
	// may use (comma-separated; "" for none). Nil: no baseline.
	CPUBaseline func(ctx context.Context) (string, error)
}

var _ admission.Handler = (*PodMutator)(nil)

// Handle implements admission.Handler.
func (m *PodMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := logf.FromContext(ctx).WithValues("namespace", req.Namespace, "uid", req.UID)
	if req.Operation != admissionv1.Create || req.Kind.Kind != "Pod" {
		return admission.Allowed("")
	}
	pod := &corev1.Pod{}
	if err := json.Unmarshal(req.Object.Raw, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}
	if pod.Namespace == "" {
		pod.Namespace = req.Namespace
	}
	dryRun := req.DryRun != nil && *req.DryRun

	// A bare-pod replacement created by the controller itself is already done.
	if pod.Annotations[v1alpha1.AnnotationRestoreID] != "" {
		return admission.Allowed("already a restore target")
	}
	if resp, intercepted := m.interceptReplacement(ctx, req, pod, dryRun, log); intercepted {
		return resp
	}
	if pod.Labels[v1alpha1.LabelMigratable] != "true" {
		return admission.Allowed("")
	}
	if _, err := v1alpha1.ParseNetworkMode(pod.Annotations[v1alpha1.AnnotationNetwork]); err != nil {
		// Invalid input, unlike an unreachable webhook (failurePolicy):
		// admitted, the pod would get a mode it did not ask for – under
		// Cilium a sticky IP, which rules out Phantom mode for its lifetime.
		return admission.Denied(fmt.Sprintf("paguro: annotation %s: %v", v1alpha1.AnnotationNetwork, err))
	}
	mutated := m.prepareMigratable(ctx, pod, log)
	return m.stickyIP(ctx, req, pod, mutated, dryRun, log)
}

// interceptReplacement turns an owner's replacement pod that a migration
// waits for into its restore target (a). intercepted reports whether a
// migration claimed the pod.
func (m *PodMutator) interceptReplacement(ctx context.Context, req admission.Request, pod *corev1.Pod, dryRun bool,
	log logr.Logger) (admission.Response, bool) {
	owner := metav1.GetControllerOf(pod)
	if owner == nil || m.Registry == nil {
		return admission.Response{}, false
	}
	var mig *v1alpha1.Migration
	var found bool
	var err error
	if dryRun {
		// Dry run: show what would happen, but consume nothing.
		if mig, found = m.Registry.Pending(ctx, owner.UID); found {
			err = MutateIntoRestoreTarget(pod, mig, netadapter.ForName(mig.Status.NetworkAdapter))
		}
	} else {
		name := pod.Name
		if name == "" {
			name = pod.GenerateName
		}
		mig, found, err = m.Registry.Consume(ctx, owner.UID, name, func(mg *v1alpha1.Migration) error {
			return MutateIntoRestoreTarget(pod, mg, netadapter.ForName(mg.Status.NetworkAdapter))
		})
	}
	if !found {
		return admission.Response{}, false
	}
	if err != nil {
		// Without mutation a normal cold-start pod is created somewhere in
		// the cluster; the controller notices this and reports Failed.
		// (mig is nil when claiming kept conflicting.)
		name := ""
		if mig != nil {
			name = mig.Name
		}
		log.Error(err, "cannot turn replacement into restore target", "migration", name)
		return admission.Allowed("").WithWarnings("paguro: replacement not restored: " + err.Error()), true
	}
	log.Info("intercepted replacement pod", "migration", mig.Name, "owner", owner.Kind+"/"+owner.Name,
		"targetNode", mig.Status.TargetNode, "dryRun", dryRun)
	return patchResponse(req.Object.Raw, pod), true
}

// prepareMigratable sets what a migratable pod needs from its start and
// reports whether it changed the pod:
//
//   - b) the RuntimeClass "paguro": only then does every container get its
//     own time namespace, from which CRIU can resume the clocks after the
//     move. An explicitly set RuntimeClass is left untouched.
//   - c) the CPU baseline (internal/cpufeat): the features the pod's
//     runtimes may use, so that it can later move to a node with an older
//     or a different CPU. paguro-runc enforces it when the containers
//     start.
func (m *PodMutator) prepareMigratable(ctx context.Context, pod *corev1.Pod, log logr.Logger) bool {
	mutated := false
	if pod.Spec.RuntimeClassName == nil {
		rc := v1alpha1.RuntimeClassName
		pod.Spec.RuntimeClassName = &rc
		mutated = true
	}
	if m.CPUBaseline != nil && pod.Annotations[v1alpha1.AnnotationCPUBaseline] == "" {
		if b, err := m.CPUBaseline(ctx); err != nil {
			log.Error(err, "no CPU baseline for the pod")
		} else if b != "" {
			if pod.Annotations == nil {
				pod.Annotations = map[string]string{}
			}
			pod.Annotations[v1alpha1.AnnotationCPUBaseline] = b
			mutated = true
		}
	}
	return mutated
}

// stickyIP gives a migratable pod under Cilium a sticky IP (d) – unless
// its migrations change its IP anyway (paguro.dev/network: phantom or
// generic):
// a sticky IP cannot be used in Phantom mode (see preflight).
func (m *PodMutator) stickyIP(ctx context.Context, req admission.Request, pod *corev1.Pod, mutated, dryRun bool,
	log logr.Logger) admission.Response {
	mode, _ := v1alpha1.ParseNetworkMode(pod.Annotations[v1alpha1.AnnotationNetwork]) // validated in Handle
	newIP := mode == v1alpha1.NetworkPhantom || mode == v1alpha1.NetworkGeneric
	if m.Sticky == nil || m.ClusterAdapter == nil || !m.ClusterAdapter().NeedsStickyIP() ||
		pod.Annotations[netadapter.AnnotationCiliumIPPool] != "" || newIP || dryRun {
		// An explicitly set pool (even a foreign one) is respected;
		// sideEffects: NoneOnDryRun – do not create pools on dry run.
		if mutated {
			return patchResponse(req.Object.Raw, pod)
		}
		return admission.Allowed("")
	}
	actx, cancel := context.WithTimeout(ctx, stickyBudget)
	defer cancel()
	pool, ip, err := m.Sticky.Allocate(actx)
	if err != nil {
		log.Error(err, "sticky IP allocation failed")
		return patchResponse(req.Object.Raw, pod).WithWarnings("paguro: no sticky IP allocated, pod will not keep its IP on migration: " + err.Error())
	}
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[netadapter.AnnotationCiliumIPPool] = pool
	pod.Annotations[v1alpha1.AnnotationStickyIP] = pool
	log.Info("allocated sticky IP", "pool", pool, "ip", ip.String(), "pod", pod.Name+pod.GenerateName)
	return patchResponse(req.Object.Raw, pod)
}

func patchResponse(original []byte, pod *corev1.Pod) admission.Response {
	b, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}
	return admission.PatchResponseFromRaw(original, b)
}
