// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"paguro.dev/paguro/api/v1alpha1"
)

// EvictionPath is the path of the eviction webhook (must match the
// MutatingWebhookConfiguration).
const EvictionPath = "/evict-v1-pod"

// LabelTrigger marks a migration that an eviction started.
const LabelTrigger = "paguro.dev/trigger"

// TriggerEviction is LabelTrigger's value for those migrations.
const TriggerEviction = "eviction"

// EvictionHandler turns the eviction of a migratable pod into a migration.
// Whoever evicts – kubectl drain, Karpenter's consolidation and spot
// interruptions, the Cluster Autoscaler – wants the pod off its node;
// moving it keeps its state and its connections where an eviction would
// restart it.
//
// The first eviction starts a migration and is answered with 429 Too Many
// Requests, which every evicter retries (as for a PodDisruptionBudget). A
// drain evicts all pods at once; the controller lets a few migrations per
// node run at a time and queues the rest (controller/queue.go). If no node
// can take the pod yet – Karpenter launches one while it drains – the
// migration waits for one (controller/targetwait.go).
// While the migration runs, retries get 429 too. Once it has succeeded the
// source pod is gone and the evicter moves on; once it has failed or rolled
// back, the next eviction is let through, and the pod is evicted as
// without Paguro. The webhook fails open: a Paguro outage never blocks a
// drain.
//
// A replacement may carry the source's name (StatefulSets, bare pods,
// Agones GameServers), and an evicter retries by name: its next eviction
// would hit the replacement on the target node. Such a retry is answered
// with 404 – the pod it means has left the node – as long as the
// replacement's own node is not being drained (staleRetry).
type EvictionHandler struct {
	// Client creates the migration.
	Client client.Client
	// Reader reads the pod and its migrations from the API server: a
	// retried eviction must see the migration created a moment ago.
	Reader client.Reader
}

var _ admission.Handler = (*EvictionHandler)(nil)

// Handle implements admission.Handler.
func (h *EvictionHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	if req.Operation != admissionv1.Create || req.SubResource != "eviction" {
		return admission.Allowed("")
	}
	if req.DryRun != nil && *req.DryRun {
		return admission.Allowed("dry run")
	}
	log := logf.FromContext(ctx).WithValues("namespace", req.Namespace, "pod", req.Name)
	pod := &corev1.Pod{}
	if err := h.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Name}, pod); err != nil {
		return admission.Allowed("") // gone, or unknown: the eviction decides
	}
	if pod.Labels[v1alpha1.LabelMigratable] != "true" || pod.DeletionTimestamp != nil || pod.Status.Phase != corev1.PodRunning {
		return admission.Allowed("")
	}
	if msg := h.staleRetry(ctx, req, pod); msg != "" {
		log.Info("eviction of a pod that has migrated – answered not found", "reason", msg)
		return gone(msg)
	}
	mig, err := h.migrationOf(ctx, pod)
	if err != nil {
		log.Error(err, "eviction: looking for the pod's migration")
		return admission.Allowed("")
	}
	switch {
	case mig == nil:
		created, err := h.start(ctx, pod)
		if err != nil {
			log.Error(err, "eviction: cannot start a migration – evicting normally")
			return admission.Allowed("")
		}
		log.Info("eviction turned into a migration", "migration", created.Name)
		return retryLater(fmt.Sprintf("paguro: migrating the pod to another node instead of evicting it (migration %s)", created.Name))
	case !mig.Status.Phase.Terminal():
		return retryLater(fmt.Sprintf("paguro: migration %s of the pod is in progress (%s)", mig.Name, phaseOrNew(mig.Status.Phase)))
	case mig.Status.Phase == v1alpha1.PhaseSucceeded:
		return admission.Allowed("migrated") // the source is being removed anyway
	default:
		return admission.Allowed(fmt.Sprintf("migration %s ended %s: evicting normally", mig.Name, mig.Status.Phase))
	}
}

// recentMigration bounds how long after a migration the evicter's retries
// are taken for stale ones.
const recentMigration = 10 * time.Minute

// staleRetry reports why an eviction is meant for a pod that has already
// migrated away ("" if it is not): the eviction's UID precondition names
// another pod, or the pod is the replacement of a recent eviction-started
// migration and its node is not being drained.
func (h *EvictionHandler) staleRetry(ctx context.Context, req admission.Request, pod *corev1.Pod) string {
	ev := &policyv1.Eviction{}
	if err := json.Unmarshal(req.Object.Raw, ev); err == nil && ev.DeleteOptions != nil &&
		ev.DeleteOptions.Preconditions != nil && ev.DeleteOptions.Preconditions.UID != nil &&
		*ev.DeleteOptions.Preconditions.UID != pod.UID {
		return fmt.Sprintf("pod %s with UID %s no longer exists (the pod of this name is its replacement)",
			pod.Name, *ev.DeleteOptions.Preconditions.UID)
	}
	id := pod.Annotations[v1alpha1.AnnotationRestoreID]
	if id == "" {
		return ""
	}
	var list v1alpha1.MigrationList
	if err := h.Reader.List(ctx, &list, client.InNamespace(pod.Namespace), client.MatchingLabels{LabelTrigger: TriggerEviction}); err != nil {
		return ""
	}
	for _, m := range list.Items {
		if string(m.UID) != id || m.Status.Phase != v1alpha1.PhaseSucceeded || m.Status.CompletedAt == nil ||
			time.Since(m.Status.CompletedAt.Time) > recentMigration || pod.Spec.NodeName == m.Status.SourceNode {
			continue
		}
		if h.beingDrained(ctx, pod.Spec.NodeName) {
			return ""
		}
		return fmt.Sprintf("pod %s left node %s (migration %s); the pod of this name now runs on %s",
			pod.Name, m.Status.SourceNode, m.Name, pod.Spec.NodeName)
	}
	return ""
}

// disruptionTaints are set on nodes that are about to go (Karpenter, the
// Cluster Autoscaler, kubectl cordon).
var disruptionTaints = map[string]bool{
	"karpenter.sh/disrupted":                    true,
	"ToBeDeletedByClusterAutoscaler":            true,
	corev1.TaintNodeUnschedulable:               true,
	"node.cloudprovider.kubernetes.io/shutdown": true,
}

// beingDrained reports whether the node is cordoned or tainted for removal.
func (h *EvictionHandler) beingDrained(ctx context.Context, name string) bool {
	n := &corev1.Node{}
	if err := h.Reader.Get(ctx, client.ObjectKey{Name: name}, n); err != nil {
		return true // unknown: take the eviction as meant
	}
	if n.Spec.Unschedulable {
		return true
	}
	for _, t := range n.Spec.Taints {
		if disruptionTaints[t.Key] {
			return true
		}
	}
	return false
}

// migrationOf returns the pod's running migration – started by an eviction
// or by anyone else – or else the one an earlier eviction of this pod
// started; nil if there is none.
func (h *EvictionHandler) migrationOf(ctx context.Context, pod *corev1.Pod) (*v1alpha1.Migration, error) {
	var list v1alpha1.MigrationList
	if err := h.Reader.List(ctx, &list, client.InNamespace(pod.Namespace)); err != nil {
		return nil, err
	}
	var ours *v1alpha1.Migration
	for i := range list.Items {
		m := &list.Items[i]
		if m.Spec.PodName != pod.Name {
			continue
		}
		if !m.Status.Phase.Terminal() {
			return m, nil
		}
		if m.Name == evictionMigrationName(pod) {
			ours = m
		}
	}
	return ours, nil
}

// start creates the migration. Its name is fixed per pod instance, so two
// evictions at once start one migration.
func (h *EvictionHandler) start(ctx context.Context, pod *corev1.Pod) (*v1alpha1.Migration, error) {
	m := &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{
			Name:      evictionMigrationName(pod),
			Namespace: pod.Namespace,
			Labels: map[string]string{
				LabelTrigger:                   TriggerEviction,
				"app.kubernetes.io/created-by": "paguro-controller",
			},
		},
		Spec: v1alpha1.MigrationSpec{PodName: pod.Name},
	}
	err := h.Client.Create(ctx, m)
	if apierrors.IsAlreadyExists(err) {
		return m, nil
	}
	return m, err
}

// evictionMigrationName: "<pod>-evict-<first 8 characters of its UID>",
// within the 63 characters of a label value (the name is used as one).
func evictionMigrationName(pod *corev1.Pod) string {
	uid := strings.ReplaceAll(string(pod.UID), "-", "")
	if len(uid) > 8 {
		uid = uid[:8]
	}
	name := pod.Name
	if limit := 63 - len("-evict-") - len(uid); len(name) > limit {
		name = strings.TrimRight(name[:limit], "-.")
	}
	return name + "-evict-" + uid
}

func phaseOrNew(p v1alpha1.Phase) string {
	if p == "" {
		return "new"
	}
	return string(p)
}

// retryLater denies the eviction with 429: evicters retry it, as for a
// PodDisruptionBudget that allows no disruption right now.
func retryLater(msg string) admission.Response {
	return admission.Response{AdmissionResponse: admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Code:    http.StatusTooManyRequests,
			Reason:  metav1.StatusReasonTooManyRequests,
			Message: msg,
		},
	}}
}

// gone answers 404: evicters take the pod as deleted and move on.
func gone(msg string) admission.Response {
	return admission.Response{AdmissionResponse: admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Code:    http.StatusNotFound,
			Reason:  metav1.StatusReasonNotFound,
			Message: "paguro: " + msg,
		},
	}}
}
