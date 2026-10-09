// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/webhook"
)

const ns = "shop"

type env struct {
	t     *testing.T
	c     client.Client
	r     *MigrationReconciler
	clock *clocktesting.FakeClock
	rec   *events.FakeRecorder
	key   types.NamespacedName
}

func testNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{
			v1alpha1.AnnotationNodeAgent: name + ":9555", v1alpha1.AnnotationNodeCPUFlags: "sse2,avx2",
		}},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			Addresses:  []corev1.NodeAddress{{Type: corev1.NodeHostName, Address: name}, {Type: corev1.NodeInternalIP, Address: fmt.Sprintf("10.42.0.%d", name[len(name)-1])}},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse("8"), corev1.ResourceMemory: resource.MustParse("16Gi"),
				corev1.ResourcePods: resource.MustParse("110"),
			},
		},
	}
}

type podOpt func(*corev1.Pod)

func ownedByRS(p *corev1.Pod) {
	p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-5d", UID: "rs-uid", Controller: ptr.To(true)}}
}

// fromDeployment gives the pod the pod-template-hash label of its ReplicaSet.
func fromDeployment(p *corev1.Pod) {
	ownedByRS(p)
	p.Labels["pod-template-hash"] = "5d"
}

func testPod(opts ...podOpt) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1", Namespace: ns, UID: "src-uid", Labels: map[string]string{"app": "web"}},
		Spec: corev1.PodSpec{
			NodeName:   "node-a",
			Containers: []corev1.Container{{Name: "app", Image: "nginx"}},
			Volumes: []corev1.Volume{
				{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}},
				{Name: "cache", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.1.5"},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func newEnv(t *testing.T, adapter netadapter.Adapter, pod *corev1.Pod, spec v1alpha1.MigrationSpec, extra ...client.Object) *env {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(gameServerGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(gameServerGVK.GroupVersion().WithKind("GameServerList"), &unstructured.UnstructuredList{})
	spec.PodName = pod.Name
	if spec.TimeoutSeconds == 0 {
		spec.TimeoutSeconds = 600
	}
	mig := &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1-abc", Namespace: ns, UID: "mig-uid"},
		Spec:       spec,
	}
	objs := []client.Object{
		testNode("node-a"), testNode("node-b"), pod, mig,
		&corev1.PersistentVolumeClaim{
			ObjectMeta: metav1.ObjectMeta{Name: "data", Namespace: ns},
			Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv-data"},
			Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound, AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}},
		},
		&corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: "pv-data"}},
		&appsv1.ReplicaSet{
			ObjectMeta: metav1.ObjectMeta{Name: "web-5d", Namespace: ns, UID: "rs-uid",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "web", UID: "dep", Controller: ptr.To(true)}}},
			// Deployment-managed: selector includes pod-template-hash.
			Spec: appsv1.ReplicaSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web", "pod-template-hash": "5d"}}},
		},
	}
	objs = append(objs, extra...)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.Migration{}, &corev1.Pod{}).
		WithIndex(&corev1.Pod{}, indexRestoreID, restoreIDOf).
		WithObjects(objs...).Build()
	clk := clocktesting.NewFakeClock(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	rec := events.NewFakeRecorder(200)
	r := &MigrationReconciler{
		Client: c, APIReader: c, Recorder: rec, Registry: webhook.NewRegistry().WithClock(clk.Now),
		Adapter: func() netadapter.Adapter { return adapter },
		Metrics: NewMetrics(prometheus.NewRegistry()), Clock: clk,
	}
	return &env{t: t, c: c, r: r, clock: clk, rec: rec, key: client.ObjectKeyFromObject(mig)}
}

func (e *env) reconcile() ctrl.Result {
	e.t.Helper()
	res, err := e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: e.key})
	if err != nil {
		e.t.Fatalf("reconcile: %v", err)
	}
	return res
}

func (e *env) mig() *v1alpha1.Migration {
	e.t.Helper()
	var m v1alpha1.Migration
	if err := e.c.Get(context.Background(), e.key, &m); err != nil {
		e.t.Fatal(err)
	}
	return &m
}

// reconcileUntil drives the reconcile loop until the phase is reached.
func (e *env) reconcileUntil(want v1alpha1.Phase) *v1alpha1.Migration {
	e.t.Helper()
	for range 10 {
		if m := e.mig(); m.Status.Phase == want {
			return m
		}
		e.reconcile()
	}
	m := e.mig()
	e.t.Fatalf("phase %s not reached, stuck in %s: %s", want, m.Status.Phase, m.Status.Message)
	return nil
}

// agent simulates an agent patch on the status (agent fields only).
func (e *env) agent(mutate func(*v1alpha1.MigrationStatus)) {
	e.t.Helper()
	m := e.mig()
	base := m.DeepCopy()
	mutate(&m.Status)
	if err := e.c.Status().Patch(context.Background(), m, client.MergeFrom(base)); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) at(d time.Duration) *metav1.MicroTime {
	t := metav1.NewMicroTime(e.clock.Now().Add(d))
	return &t
}

func (e *env) sourceExists() bool {
	var p corev1.Pod
	err := e.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "web-1"}, &p)
	return err == nil && p.UID == "src-uid"
}

// targetPod returns the target pod recorded in the migration status.
func (e *env) targetPod() *corev1.Pod {
	e.t.Helper()
	var p corev1.Pod
	name := e.mig().Status.TargetPodName
	if err := e.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &p); err != nil {
		e.t.Fatalf("target pod %q: %v", name, err)
	}
	return &p
}

// warmUp runs the reconcile in PreCopy (early replacement pod).
func (e *env) warmUp() {
	e.t.Helper()
	for range 3 {
		e.reconcile()
	}
}

func (e *env) freeze() {
	e.agent(func(st *v1alpha1.MigrationStatus) {
		st.Source.Accepted = true
		st.Source.FrozenAt = e.at(0)
		st.Phase = v1alpha1.PhaseFrozen
		st.Timings.PreCopyMs = 1234 // agent field: must not be overwritten
		st.WireBytes = 64 << 20
	})
}

func TestHappyPathReplicaSet(t *testing.T) {
	e := newEnv(t, netadapter.Calico{}, testPod(ownedByRS), v1alpha1.MigrationSpec{})

	m := e.reconcileUntil(v1alpha1.PhasePreCopy)
	if m.Status.TargetNode != "node-b" || m.Status.SourceNode != "node-a" || m.Status.SourcePodIP != "10.0.1.5" {
		t.Fatalf("preflight result: %+v", m.Status)
	}
	if m.Status.OwnerKind != "Deployment" || m.Status.OwnerName != "web" || m.Status.Cutover.ReplacementOwnerUID != "rs-uid" {
		t.Errorf("owner: %s/%s uid=%s", m.Status.OwnerKind, m.Status.OwnerName, m.Status.Cutover.ReplacementOwnerUID)
	}
	if !m.Status.IPPreserved || m.Status.NetworkAdapter != "calico" {
		t.Errorf("network: %s preserved=%v", m.Status.NetworkAdapter, m.Status.IPPreserved)
	}
	if len(m.Status.Volumes) != 2 || m.Status.Volumes[0].Kind != VolumePVCRWO || m.Status.Volumes[1].Kind != VolumeEmptyDir {
		t.Errorf("volumes: %+v", m.Status.Volumes)
	}
	if !strings.Contains(m.Annotations[webhook.AnnotationSourcePod], `"web-1"`) || len(m.Finalizers) != 1 {
		t.Errorf("source pod snapshot / finalizer missing")
	}

	// PreCopy: delete nothing, no matter how often we reconcile.
	e.reconcile()
	e.reconcile()
	if !e.sourceExists() {
		t.Fatal("source pod deleted before Frozen")
	}
	if _, ok := e.r.Registry.Pending(context.Background(), "rs-uid"); ok {
		t.Fatal("replacement registered before Frozen")
	}

	e.freeze()
	e.clock.Step(80 * time.Millisecond)
	m = e.reconcileUntil(v1alpha1.PhaseCuttingOver)
	if e.sourceExists() {
		t.Fatal("source pod should be deleted in CuttingOver")
	}
	if m.Status.Timings.PreCopyMs != 1234 || m.Status.WireBytes != 64<<20 {
		t.Errorf("controller clobbered agent fields: %+v", m.Status.Timings)
	}
	pending, ok := e.r.Registry.Pending(context.Background(), "rs-uid")
	if !ok || pending.Status.TargetNode != "node-b" {
		t.Fatal("replacement not registered for webhook")
	}

	// Webhook: the ReplicaSet creates the replacement, which gets mutated.
	e.clock.Step(40 * time.Millisecond)
	repl := testPod(ownedByRS)
	repl.Name, repl.UID, repl.Status = "web-2", "dst-uid", corev1.PodStatus{Phase: corev1.PodPending}
	if _, _, err := e.r.Registry.Consume(context.Background(), "rs-uid", "", func(mg *v1alpha1.Migration) error {
		return webhook.MutateIntoRestoreTarget(repl, mg, netadapter.Calico{})
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Create(context.Background(), repl); err != nil {
		t.Fatal(err)
	}
	m = e.reconcileUntil(v1alpha1.PhaseRestoring)
	if m.Status.TargetPodName != "web-2" || m.Status.Timings.CutoverMs < 0 {
		t.Fatalf("restoring: %+v", m.Status)
	}

	// Not restored yet → stays in Restoring.
	e.reconcile()
	if e.mig().Status.Phase != v1alpha1.PhaseRestoring {
		t.Fatal("must wait for restoredAt")
	}

	// Volume: detach on source, attach on target.
	pv := "pv-data"
	if err := e.c.Create(context.Background(), &storagev1.VolumeAttachment{
		ObjectMeta: metav1.ObjectMeta{Name: "va-b"},
		Spec:       storagev1.VolumeAttachmentSpec{NodeName: "node-b", Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pv}},
		Status:     storagev1.VolumeAttachmentStatus{Attached: true},
	}); err != nil {
		t.Fatal(err)
	}
	e.clock.Step(200 * time.Millisecond)
	e.agent(func(st *v1alpha1.MigrationStatus) {
		st.Target.RestoredAt = e.at(0)
		st.Target.Containers = []v1alpha1.TargetContainerStatus{{Name: "app", Restored: true, RestoreMs: 150}}
	})
	repl.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.1.5"}
	if err := e.c.Status().Update(context.Background(), repl); err != nil {
		t.Fatal(err)
	}
	e.clock.Step(10 * time.Millisecond)
	m = e.reconcileUntil(v1alpha1.PhaseSucceeded)

	tm := m.Status.Timings
	if tm.FreezeMs != 320 { // 80 + 40 + 200 ms
		t.Errorf("freeze = %d, want 320", tm.FreezeMs)
	}
	if tm.TotalMs <= 0 || tm.RestoreMs <= 0 || tm.VolumeMoveMs <= 0 {
		t.Errorf("timings incomplete: %+v", tm)
	}
	if m.Status.TargetPodIP != "10.0.1.5" || m.Status.CompletedAt == nil || len(m.Finalizers) != 0 {
		// The finalizer disappears with the next reconcile.
		e.reconcile()
		if m = e.mig(); len(m.Finalizers) != 0 {
			t.Errorf("finalizer not removed")
		}
	}
	if c := meta.FindStatusCondition(m.Status.Conditions, ConditionRestored); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Restored condition: %+v", c)
	}
	if got := testutil.ToFloat64(e.r.Metrics.Total.WithLabelValues("Succeeded")); got != 1 {
		t.Errorf("migrations_total{Succeeded} = %v", got)
	}
	if testutil.CollectAndCount(e.r.Metrics.Freeze) != 1 {
		t.Error("freeze histogram not observed")
	}
	if _, ok := e.r.Registry.ConsumedAt(&v1alpha1.Migration{ObjectMeta: metav1.ObjectMeta{UID: "mig-uid"}}); ok {
		t.Error("registry entry must be forgotten at terminal phase")
	}
	assertEvent(t, e.rec, "Succeeded")
}

func assertEvent(t *testing.T, rec *events.FakeRecorder, substr string) {
	t.Helper()
	for {
		select {
		case ev := <-rec.Events:
			if strings.Contains(ev, substr) {
				return
			}
		default:
			t.Errorf("no event containing %q", substr)
			return
		}
	}
}

func TestBarePodIsRecreatedAsRestoreTarget(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(), v1alpha1.MigrationSpec{})
	m := e.reconcileUntil(v1alpha1.PhasePreCopy)
	if m.Status.Cutover.ReplacementOwnerUID != "" || m.Status.IPPreserved {
		t.Fatalf("bare pod / generic: %+v", m.Status)
	}
	e.freeze()
	e.reconcileUntil(v1alpha1.PhaseRestoring)

	p := e.targetPod()
	if p.Name != "web-1-pmigui" || e.sourceExists() {
		t.Fatalf("want warm target web-1-pmigui and source gone, got %s (source exists: %v)", p.Name, e.sourceExists())
	}
	if m := e.mig(); m.Status.Cutover.Mode != v1alpha1.CutoverEarly || m.Status.Timings.CutoverMs != 0 {
		t.Errorf("bare pods use early mode: %+v", m.Status.Cutover)
	}
	if p.Spec.NodeName != "node-b" || p.Annotations[v1alpha1.AnnotationRestoreID] != "mig-uid" ||
		p.Annotations[v1alpha1.AnnotationTCP] != "close" || *p.Spec.RuntimeClassName != "paguro" {
		t.Fatalf("replacement not a restore target: node=%s ann=%v", p.Spec.NodeName, p.Annotations)
	}
}

func TestPreflightRejections(t *testing.T) {
	cases := []struct {
		name string
		pod  podOpt
		spec v1alpha1.MigrationSpec
		want string
	}{
		{"hostNetwork", func(p *corev1.Pod) { p.Spec.HostNetwork = true }, v1alpha1.MigrationSpec{}, "hostNetwork"},
		{"hostPath", func(p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "h", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}})
		}, v1alpha1.MigrationSpec{}, "hostPath"},
		{"tty", func(p *corev1.Pod) { p.Spec.Containers[0].TTY = true }, v1alpha1.MigrationSpec{}, "tty"},
		{"gpu", func(p *corev1.Pod) {
			p.Spec.Containers[0].Resources.Limits = corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("1")}
		}, v1alpha1.MigrationSpec{}, "device resource"},
		{"daemonset", func(p *corev1.Pod) {
			p.OwnerReferences = []metav1.OwnerReference{{Kind: "DaemonSet", Name: "ds", UID: "x", Controller: ptr.To(true)}}
		}, v1alpha1.MigrationSpec{}, "DaemonSet"},
		{"mirror", func(p *corev1.Pod) { p.Annotations = map[string]string{corev1.MirrorPodAnnotationKey: "x"} }, v1alpha1.MigrationSpec{}, "mirror"},
		{"not running", func(p *corev1.Pod) { p.Status.Phase = corev1.PodPending }, v1alpha1.MigrationSpec{}, "not running"},
		{"preserve impossible", func(*corev1.Pod) {}, v1alpha1.MigrationSpec{Network: v1alpha1.NetworkPreserve}, "Preserve"},
		{"target is source", func(*corev1.Pod) {}, v1alpha1.MigrationSpec{TargetNode: "node-a"}, "target equals source"},
		{"unknown target", func(*corev1.Pod) {}, v1alpha1.MigrationSpec{TargetNode: "nope"}, "does not exist"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, netadapter.Generic{}, testPod(tt.pod), tt.spec)
			m := e.reconcileUntil(v1alpha1.PhaseFailed)
			if !strings.Contains(m.Status.Message, tt.want) {
				t.Errorf("message %q lacks %q", m.Status.Message, tt.want)
			}
			if !e.sourceExists() {
				t.Error("preflight failure must never touch the pod")
			}
			e.reconcile()
			if len(e.mig().Finalizers) != 0 {
				t.Error("finalizer must be removed in terminal phase")
			}
		})
	}
}

func TestPreflightCPUStrictExplicitTarget(t *testing.T) {
	old := testNode("node-old")
	old.Annotations[v1alpha1.AnnotationNodeCPUFlags] = "sse2"
	e := newEnv(t, netadapter.Generic{}, testPod(), v1alpha1.MigrationSpec{TargetNode: "node-old", CPUPolicy: v1alpha1.CPUStrict}, old)
	m := e.reconcileUntil(v1alpha1.PhaseFailed)
	if !strings.Contains(m.Status.Message, "avx2") {
		t.Errorf("message must list missing flags: %q", m.Status.Message)
	}

	e = newEnv(t, netadapter.Generic{}, testPod(), v1alpha1.MigrationSpec{TargetNode: "node-old", CPUPolicy: v1alpha1.CPUIgnore}, old)
	m = e.reconcileUntil(v1alpha1.PhasePreCopy)
	if !strings.Contains(strings.Join(m.Status.Warnings, " "), "avx2") {
		t.Errorf("warnings must list missing flags: %v", m.Status.Warnings)
	}
}

func TestConcurrentMigrationOfSamePodRejected(t *testing.T) {
	other := &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1-older", Namespace: ns, UID: "other"},
		Spec:       v1alpha1.MigrationSpec{PodName: "web-1"},
		Status:     v1alpha1.MigrationStatus{Phase: v1alpha1.PhasePreCopy},
	}
	e := newEnv(t, netadapter.Generic{}, testPod(), v1alpha1.MigrationSpec{}, other)
	m := e.reconcileUntil(v1alpha1.PhaseFailed)
	if !strings.Contains(m.Status.Message, "already being migrated") {
		t.Errorf("got %q", m.Status.Message)
	}
}

func TestPreCopyTimeoutRollsBack(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(ownedByRS), v1alpha1.MigrationSpec{TimeoutSeconds: 30})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	res := e.reconcile()
	if res.RequeueAfter <= 0 || res.RequeueAfter > 30*time.Second {
		t.Errorf("expected requeue at timeout, got %v", res.RequeueAfter)
	}
	e.agent(func(st *v1alpha1.MigrationStatus) { st.Source.Accepted = true })
	e.clock.Step(31 * time.Second)
	m := e.reconcileUntil(v1alpha1.PhaseAborting)
	if !strings.Contains(m.Status.Message, "timeout") {
		t.Errorf("message: %q", m.Status.Message)
	}
	e.reconcile()
	if e.mig().Status.Phase != v1alpha1.PhaseAborting {
		t.Fatal("must wait for thawedAt")
	}
	e.agent(func(st *v1alpha1.MigrationStatus) { st.Source.ThawedAt = e.at(0) })
	m = e.reconcileUntil(v1alpha1.PhaseRolledBack)
	if !e.sourceExists() {
		t.Fatal("rollback must keep the source pod")
	}
	if c := meta.FindStatusCondition(m.Status.Conditions, ConditionRestored); c == nil || c.Reason != ReasonRolledBack {
		t.Errorf("condition: %+v", c)
	}
}

// A source agent that does not pick the migration up is not waited for to
// the end of the timeout.
func TestSourcePickupTimeout(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(ownedByRS), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	if res := e.reconcile(); res.RequeueAfter <= 0 || res.RequeueAfter > SourcePickupTimeout {
		t.Errorf("expected a requeue at the pickup timeout, got %v", res.RequeueAfter)
	}
	e.clock.Step(SourcePickupTimeout + time.Second)
	e.reconcileUntil(v1alpha1.PhaseAborting)
	e.clock.Step(AbortTimeout) // nothing to thaw: nobody froze anything
	m := e.reconcileUntil(v1alpha1.PhaseRolledBack)
	if !strings.Contains(m.Status.Message, "did not pick up the migration within 1m30s") {
		t.Errorf("message: %q", m.Status.Message)
	}
	if !e.sourceExists() {
		t.Fatal("rollback must keep the source pod")
	}
}

func TestSourceErrorAbortsAndThawTimeoutFails(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.agent(func(st *v1alpha1.MigrationStatus) {
		st.Source.Accepted = true
		st.Source.Error = "criu dump failed"
	})
	e.reconcileUntil(v1alpha1.PhaseAborting)
	e.clock.Step(AbortTimeout + time.Second)
	m := e.reconcileUntil(v1alpha1.PhaseFailed)
	if !strings.Contains(m.Status.Message, "source may still be frozen") {
		t.Errorf("message: %q", m.Status.Message)
	}
	assertEvent(t, e.rec, "SourceMayBeFrozen")
}

func TestAbortWithoutAgentRollsBack(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(), v1alpha1.MigrationSpec{TimeoutSeconds: 10})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.clock.Step(11 * time.Second)
	e.reconcileUntil(v1alpha1.PhaseAborting)
	e.clock.Step(AbortTimeout + time.Second)
	m := e.reconcileUntil(v1alpha1.PhaseRolledBack)
	if !strings.Contains(m.Status.Message, "nothing was frozen") {
		t.Errorf("message: %q", m.Status.Message)
	}
}

func TestReplacementTimeoutFails(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(ownedByRS), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.freeze()
	e.reconcileUntil(v1alpha1.PhaseCuttingOver)
	e.reconcile()
	if e.mig().Status.Phase != v1alpha1.PhaseCuttingOver {
		t.Fatal("must wait for replacement")
	}
	e.clock.Step(TargetPodTimeout + time.Second)
	m := e.reconcileUntil(v1alpha1.PhaseFailed)
	if !strings.Contains(m.Status.Message, "no rollback possible") {
		t.Errorf("message: %q", m.Status.Message)
	}
}

func TestEscapedReplacementFails(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(ownedByRS), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.freeze()
	e.reconcileUntil(v1alpha1.PhaseCuttingOver)
	// The webhook did not intercept: a regular ReplicaSet pod.
	escaped := testPod(ownedByRS)
	escaped.Name, escaped.UID = "web-3", "esc"
	escaped.CreationTimestamp = metav1.NewTime(e.clock.Now())
	if err := e.c.Create(context.Background(), escaped); err != nil {
		t.Fatal(err)
	}
	m := e.reconcileUntil(v1alpha1.PhaseFailed)
	if !strings.Contains(m.Status.Message, "web-3") || !strings.Contains(m.Status.Message, "cold-started") {
		t.Errorf("message: %q", m.Status.Message)
	}
}

func TestColdStartSucceedsWithCondition(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.freeze()
	e.reconcileUntil(v1alpha1.PhaseRestoring)
	p := e.targetPod()
	p.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.9.9"}
	if err := e.c.Status().Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	e.agent(func(st *v1alpha1.MigrationStatus) {
		st.Target.Containers = []v1alpha1.TargetContainerStatus{{Name: "app", ColdStartReason: "criu restore: mount mismatch"}}
	})
	m := e.reconcileUntil(v1alpha1.PhaseSucceeded)
	c := meta.FindStatusCondition(m.Status.Conditions, ConditionRestored)
	if c == nil || c.Status != metav1.ConditionFalse || c.Reason != ReasonColdStart {
		t.Fatalf("condition: %+v", c)
	}
	if m.Status.TargetPodIP != "10.0.9.9" {
		t.Errorf("target IP %q", m.Status.TargetPodIP)
	}
	assertEvent(t, e.rec, ReasonColdStart)
}

func TestReadinessWait(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(func(p *corev1.Pod) {
		p.Spec.Containers[0].ReadinessProbe = &corev1.Probe{}
	}), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.freeze()
	e.reconcileUntil(v1alpha1.PhaseRestoring)
	p := e.targetPod()
	p.Status = corev1.PodStatus{Phase: corev1.PodRunning}
	_ = e.c.Status().Update(context.Background(), p)
	e.agent(func(st *v1alpha1.MigrationStatus) { st.Target.RestoredAt = e.at(0) })
	e.reconcile()
	if e.mig().Status.Phase != v1alpha1.PhaseRestoring {
		t.Fatal("must wait for Ready")
	}
	e.clock.Step(ReadyWait + time.Second)
	m := e.reconcileUntil(v1alpha1.PhaseSucceeded)
	if !strings.Contains(strings.Join(m.Status.Warnings, " "), "not Ready") {
		t.Errorf("warnings: %v", m.Status.Warnings)
	}
}

func TestDeletingMigrationDuringPreCopyAborts(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	if err := e.c.Delete(context.Background(), e.mig()); err != nil {
		t.Fatal(err)
	}
	m := e.reconcileUntil(v1alpha1.PhaseAborting)
	if m.DeletionTimestamp.IsZero() {
		t.Fatal("finalizer must keep the object while aborting")
	}
	e.agent(func(st *v1alpha1.MigrationStatus) { st.Source.ThawedAt = e.at(0) })
	e.reconcileUntil(v1alpha1.PhaseRolledBack)
	e.reconcile()
	err := e.c.Get(context.Background(), e.key, &v1alpha1.Migration{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("migration should be gone after finalizer removal, got %v", err)
	}
}

func TestRestartReRegistersPendingReplacement(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(ownedByRS), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.freeze()
	e.reconcileUntil(v1alpha1.PhaseCuttingOver)
	// Restart: registry empty.
	e.r.Registry = webhook.NewRegistry().WithClock(e.clock.Now)
	e.reconcile()
	if _, ok := e.r.Registry.Pending(context.Background(), "rs-uid"); !ok {
		t.Fatal("pending replacement not re-registered from status")
	}
}

func TestConflictIsRequeuedNotActedTwice(t *testing.T) {
	e := newEnv(t, netadapter.Generic{}, testPod(ownedByRS), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.freeze()
	// Stale copy: the optimistic lock must prevent the second transition.
	stale := e.mig()
	e.reconcileUntil(v1alpha1.PhaseCuttingOver)
	err := e.r.transition(context.Background(), stale, v1alpha1.PhaseCuttingOver, "again", nil)
	if !apierrors.IsConflict(err) {
		t.Fatalf("expected conflict on stale transition, got %v", err)
	}
	if stale.Status.Phase != v1alpha1.PhaseFrozen {
		t.Error("in-memory object must be restored after failed patch")
	}
}

// interceptReplacement simulates ReplicaSet + webhook: the RS creates a pod
// with generateName, the webhook turns it into the restore target.
func (e *env) interceptReplacement() *corev1.Pod {
	e.t.Helper()
	repl := testPod(fromDeployment)
	repl.Name, repl.GenerateName, repl.UID = "", "web-5d-", "dst-uid"
	repl.Status = corev1.PodStatus{Phase: corev1.PodPending}
	_, found, err := e.r.Registry.Consume(context.Background(), "rs-uid", "", func(mg *v1alpha1.Migration) error {
		return webhook.MutateIntoRestoreTarget(repl, mg, netadapter.ForName(mg.Status.NetworkAdapter))
	})
	if err != nil || !found {
		e.t.Fatalf("webhook interception: found=%v err=%v", found, err)
	}
	if err := e.c.Create(context.Background(), repl); err != nil {
		e.t.Fatal(err)
	}
	return repl
}

func (e *env) source() *corev1.Pod {
	e.t.Helper()
	var p corev1.Pod
	if err := e.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "web-1"}, &p); err != nil {
		e.t.Fatal(err)
	}
	return &p
}

func TestEarlyReplacementDeployment(t *testing.T) {
	e := newEnv(t, netadapter.Calico{}, testPod(fromDeployment), v1alpha1.MigrationSpec{})
	m := e.reconcileUntil(v1alpha1.PhasePreCopy)
	if m.Status.Cutover.Mode != v1alpha1.CutoverEarly || m.Status.Cutover.OriginalPodTemplateHash != "5d" {
		t.Fatalf("cutover: %+v", m.Status.Cutover)
	}
	e.agent(func(st *v1alpha1.MigrationStatus) { st.Source.Accepted = true })

	// PreCopy: the source is detached from the RS, the webhook is armed.
	e.warmUp()
	m = e.mig()
	if m.Status.TargetPodName != "web-5d-pmigui" || m.Status.Cutover.ReplacementRequestedAt == nil {
		t.Fatalf("early target not requested: %q %+v", m.Status.TargetPodName, m.Status.Cutover)
	}
	src := e.source()
	if src.Labels["pod-template-hash"] != "5d-paguro-migui" || src.Annotations[AnnotationOriginalHash] != "5d" {
		t.Fatalf("source not detached: labels=%v ann=%v", src.Labels, src.Annotations)
	}
	if _, ok := e.r.Registry.Pending(context.Background(), "rs-uid"); !ok {
		t.Fatal("replacement not registered")
	}

	e.clock.Step(230 * time.Millisecond)
	repl := e.interceptReplacement()
	if repl.Name != "web-5d-pmigui" {
		t.Fatalf("webhook name %q", repl.Name)
	}
	e.reconcile()
	m = e.mig()
	if m.Status.Phase != v1alpha1.PhasePreCopy || m.Status.TargetPodUID != "dst-uid" || m.Status.Cutover.TargetPodCreatedAt == nil {
		t.Fatalf("warm target not recorded: %+v", m.Status)
	}
	// ContainerCreating for a long time is fine during pre-copy.
	e.clock.Step(2 * TargetPodTimeout)
	e.reconcile()
	if e.mig().Status.Phase != v1alpha1.PhasePreCopy || !e.sourceExists() {
		t.Fatal("waiting warm target must not abort or touch the source")
	}

	e.freeze()
	m = e.reconcileUntil(v1alpha1.PhaseRestoring)
	if e.sourceExists() {
		t.Fatal("source must be deleted at cutover")
	}
	if m.Status.TargetPodName != "web-5d-pmigui" || m.Status.Timings.CutoverMs != 0 {
		t.Errorf("restoring: %s cutoverMs=%d", m.Status.TargetPodName, m.Status.Timings.CutoverMs)
	}

	e.clock.Step(150 * time.Millisecond)
	e.agent(func(st *v1alpha1.MigrationStatus) {
		st.Target.RestoredAt = e.at(0)
		st.Target.Containers = []v1alpha1.TargetContainerStatus{{Name: "app", Restored: true}}
	})
	repl.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.1.5"}
	if err := e.c.Status().Update(context.Background(), repl); err != nil {
		t.Fatal(err)
	}
	m = e.reconcileUntil(v1alpha1.PhaseSucceeded)
	if m.Status.Timings.FreezeMs != 150 {
		t.Errorf("freeze = %d, want 150", m.Status.Timings.FreezeMs)
	}
	assertEvent(t, e.rec, "WarmTarget")
}

func TestEarlyReplacementRollback(t *testing.T) {
	e := newEnv(t, netadapter.Calico{}, testPod(fromDeployment), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.warmUp()
	e.interceptReplacement()
	e.reconcile()

	e.agent(func(st *v1alpha1.MigrationStatus) {
		st.Source.Accepted = true
		st.Source.Error = "criu dump failed"
	})
	e.reconcileUntil(v1alpha1.PhaseAborting)
	e.reconcile()

	var repl corev1.Pod
	err := e.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "web-5d-pmigui"}, &repl)
	if !apierrors.IsNotFound(err) {
		t.Fatalf("warm target must be deleted on rollback, got %v", err)
	}
	src := e.source()
	if src.Labels["pod-template-hash"] != "5d" {
		t.Errorf("label not restored: %v", src.Labels)
	}
	if _, ok := src.Annotations[AnnotationOriginalHash]; ok {
		t.Error("original-hash annotation must be removed")
	}
	if _, ok := e.r.Registry.Pending(context.Background(), "rs-uid"); ok {
		t.Error("pending registry entry must be cleared")
	}

	e.agent(func(st *v1alpha1.MigrationStatus) { st.Source.ThawedAt = e.at(0) })
	e.reconcileUntil(v1alpha1.PhaseRolledBack)
	if !e.sourceExists() {
		t.Fatal("source must survive rollback")
	}
}

// A rolled-back migration's clean-up runs again on every resync (a new
// leader); by then the pod may be detached by a later migration, whose
// label it must leave alone.
func TestRolledBackMigrationLeavesALaterMigrationsLabel(t *testing.T) {
	e := newEnv(t, netadapter.Calico{}, testPod(fromDeployment), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.warmUp()
	e.interceptReplacement()
	e.reconcile()
	e.agent(func(st *v1alpha1.MigrationStatus) {
		st.Source.Accepted = true
		st.Source.Error = "criu dump failed"
	})
	e.reconcileUntil(v1alpha1.PhaseAborting)
	e.agent(func(st *v1alpha1.MigrationStatus) { st.Source.ThawedAt = e.at(0) })
	e.reconcileUntil(v1alpha1.PhaseRolledBack)

	// The next migration of the same pod detaches it under its own hash.
	src := e.source()
	src.Labels["pod-template-hash"] = "5d-paguro-later"
	src.Annotations = map[string]string{AnnotationOriginalHash: "5d"}
	if err := e.c.Update(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	e.reconcile()
	e.reconcile()
	if src := e.source(); src.Labels["pod-template-hash"] != "5d-paguro-later" || src.Annotations[AnnotationOriginalHash] != "5d" {
		t.Fatalf("the ended migration handed the pod back to the ReplicaSet: labels=%v ann=%v", src.Labels, src.Annotations)
	}
}

func TestEarlyReplacementCleanedUpOnFailure(t *testing.T) {
	e := newEnv(t, netadapter.Calico{}, testPod(fromDeployment), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.warmUp()
	e.interceptReplacement()
	e.reconcile()
	// Failure without Aborting (e.g. controller reports Failed directly).
	m := e.mig()
	if err := e.r.fail(context.Background(), m, "synthetic"); err != nil {
		t.Fatal(err)
	}
	e.reconcile()
	e.reconcile()
	if src := e.source(); src.Labels["pod-template-hash"] != "5d" {
		t.Errorf("label not restored after failure: %v", src.Labels)
	}
	if len(e.mig().Finalizers) != 0 {
		t.Error("finalizer must be removed once cleanup is done")
	}
}

func TestStatefulSetStaysOnDelete(t *testing.T) {
	sts := func(p *corev1.Pod) {
		p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "StatefulSet", Name: "db", UID: "sts-uid", Controller: ptr.To(true)}}
		p.Labels["pod-template-hash"] = "x" // irrelevant for StatefulSets
	}
	e := newEnv(t, netadapter.Generic{}, testPod(sts), v1alpha1.MigrationSpec{})
	m := e.reconcileUntil(v1alpha1.PhasePreCopy)
	if m.Status.Cutover.Mode != v1alpha1.CutoverOnDelete {
		t.Fatalf("mode %q, want on-delete", m.Status.Cutover.Mode)
	}
	e.warmUp()
	if m = e.mig(); m.Status.TargetPodName != "" || m.Status.Cutover.ReplacementRequestedAt != nil {
		t.Errorf("no early replacement expected: %+v", m.Status.Cutover)
	}
	if _, ok := e.r.Registry.Pending(context.Background(), "sts-uid"); ok {
		t.Error("must not register before Frozen")
	}
	if e.source().Labels["pod-template-hash"] != "x" {
		t.Error("source labels must stay untouched")
	}
	e.freeze()
	e.reconcileUntil(v1alpha1.PhaseCuttingOver)
	if _, ok := e.r.Registry.Pending(context.Background(), "sts-uid"); !ok || e.sourceExists() {
		t.Error("on-delete: register + delete at cutover")
	}
}

func TestPlainReplicaSetStaysOnDelete(t *testing.T) {
	// ReplicaSet without pod-template-hash label on the pod → on-delete.
	e := newEnv(t, netadapter.Generic{}, testPod(ownedByRS), v1alpha1.MigrationSpec{})
	if m := e.reconcileUntil(v1alpha1.PhasePreCopy); m.Status.Cutover.Mode != v1alpha1.CutoverOnDelete {
		t.Fatalf("mode %q", m.Status.Cutover.Mode)
	}
}

// A delete of the source that fails at the commit (API error, leadership
// lost in between) is retried on the next steps.
func TestSourceDeleteRetriedAfterCommit(t *testing.T) {
	e := newEnv(t, netadapter.Calico{}, testPod(fromDeployment), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.warmUp()
	e.interceptReplacement()
	e.reconcile()

	failures := 2
	e.r.Client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(*corev1.Pod); ok && obj.GetName() == "web-1" && failures > 0 {
				failures--
				return errors.New("connection refused")
			}
			return c.Delete(ctx, obj, opts...)
		},
	})
	e.freeze()
	for range 5 {
		_, _ = e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: e.key})
		if e.mig().Status.Phase == v1alpha1.PhaseRestoring {
			break
		}
	}
	if m := e.mig(); m.Status.Phase != v1alpha1.PhaseRestoring || e.sourceExists() || failures != 0 {
		t.Fatalf("phase %s, source exists %v, failures left %d", m.Status.Phase, e.sourceExists(), failures)
	}
}

// The migration does not succeed while the frozen source is still there:
// the source is deleted first, with a warning.
func TestNoSuccessWhileSourceExists(t *testing.T) {
	e := newEnv(t, netadapter.Calico{}, testPod(fromDeployment), v1alpha1.MigrationSpec{})
	e.reconcileUntil(v1alpha1.PhasePreCopy)
	e.warmUp()
	repl := e.interceptReplacement()
	e.reconcile()
	e.freeze()
	e.reconcileUntil(v1alpha1.PhaseRestoring)

	// The delete never reached the API server.
	src := testPod(fromDeployment)
	if err := e.c.Create(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	e.agent(func(st *v1alpha1.MigrationStatus) {
		st.Target.RestoredAt = e.at(0)
		st.Target.Containers = []v1alpha1.TargetContainerStatus{{Name: "app", Restored: true}}
	})
	repl.Status = corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.0.1.5"}
	if err := e.c.Status().Update(context.Background(), repl); err != nil {
		t.Fatal(err)
	}
	// As long as the source cannot be deleted, the migration does not end.
	blocked := true
	e.r.Client = interceptor.NewClient(e.c.(client.WithWatch), interceptor.Funcs{
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if _, ok := obj.(*corev1.Pod); ok && obj.GetName() == "web-1" && blocked {
				return errors.New("connection refused")
			}
			return c.Delete(ctx, obj, opts...)
		},
	})
	for range 3 {
		_, _ = e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: e.key})
	}
	if m := e.mig(); m.Status.Phase != v1alpha1.PhaseRestoring {
		t.Fatalf("phase %s with the source still there", m.Status.Phase)
	}
	blocked = false
	e.reconcileUntil(v1alpha1.PhaseSucceeded)
	if e.sourceExists() {
		t.Fatal("succeeded with the source still there")
	}
	assertEvent(t, e.rec, "SourceNotDeleted")
}

// A pod still carrying an earlier migration's detached hash: its
// ReplicaSet's hash comes from the annotation; without it the preflight
// refuses (hashes would stack and a rollback never reach the ReplicaSet).
func TestPreflightOnStillDetachedPod(t *testing.T) {
	detached := func(withAnnotation bool) podOpt {
		return func(p *corev1.Pod) {
			fromDeployment(p)
			p.Labels["pod-template-hash"] = "5d-paguro-older"
			if withAnnotation {
				p.Annotations = map[string]string{AnnotationOriginalHash: "5d"}
			}
		}
	}
	e := newEnv(t, netadapter.Calico{}, testPod(detached(true)), v1alpha1.MigrationSpec{})
	if m := e.reconcileUntil(v1alpha1.PhasePreCopy); m.Status.Cutover.OriginalPodTemplateHash != "5d" {
		t.Fatalf("original hash %q, want the ReplicaSet's 5d", m.Status.Cutover.OriginalPodTemplateHash)
	}
	e = newEnv(t, netadapter.Calico{}, testPod(detached(false)), v1alpha1.MigrationSpec{})
	if m := e.reconcileUntil(v1alpha1.PhaseFailed); !strings.Contains(m.Status.Message, "still detached") {
		t.Fatalf("message %q", m.Status.Message)
	}
}

// An ended migration records when it released the pod; a new migration of
// the same pod waits for that (bounded), and the clean-up does not run again.
func TestNewMigrationWaitsForRelease(t *testing.T) {
	changed := metav1.NewMicroTime(time.Date(2026, 10, 1, 11, 59, 30, 0, time.UTC))
	ended := &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1-old", Namespace: ns, UID: "old-uid"},
		Spec:       v1alpha1.MigrationSpec{PodName: "web-1"},
		Status: v1alpha1.MigrationStatus{Phase: v1alpha1.PhaseRolledBack, SourcePodUID: "src-uid",
			PhaseChangedAt: &changed},
	}
	e := newEnv(t, netadapter.Calico{}, testPod(fromDeployment), v1alpha1.MigrationSpec{}, ended)
	e.reconcile()
	e.reconcile()
	if p := e.mig().Status.Phase; p != v1alpha1.PhasePreflight {
		t.Fatalf("phase %s: the new migration must wait for the ended one to release the pod", p)
	}
	// The ended migration's clean-up runs once and records it.
	old := &v1alpha1.Migration{}
	key := types.NamespacedName{Namespace: ns, Name: "web-1-old"}
	if _, err := e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Get(context.Background(), key, old); err != nil || old.Status.ReleasedAt == nil {
		t.Fatalf("releasedAt not recorded: %v %+v", err, old.Status)
	}
	e.reconcileUntil(v1alpha1.PhasePreCopy)
}

// The wait is bounded: a clean-up that never finishes does not block the pod.
func TestNewMigrationDoesNotWaitForever(t *testing.T) {
	changed := metav1.NewMicroTime(time.Date(2026, 10, 1, 11, 0, 0, 0, time.UTC))
	ended := &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "web-1-old", Namespace: ns, UID: "old-uid"},
		Spec:       v1alpha1.MigrationSpec{PodName: "web-1"},
		Status: v1alpha1.MigrationStatus{Phase: v1alpha1.PhaseFailed, SourcePodUID: "src-uid",
			PhaseChangedAt: &changed},
	}
	e := newEnv(t, netadapter.Calico{}, testPod(fromDeployment), v1alpha1.MigrationSpec{}, ended)
	e.reconcileUntil(v1alpha1.PhasePreCopy)
}
