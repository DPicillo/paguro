// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package webhook

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jsonpatchv5 "github.com/evanphx/json-patch/v5"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/gate"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/pkg/names"
)

const ownerUID = types.UID("rs-uid")

func sourcePod() *corev1.Pod {
	always := corev1.ContainerRestartPolicyAlways
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "web-abc", Namespace: "shop", UID: "pod-uid",
			Labels:          map[string]string{"app": "web", v1alpha1.LabelMigratable: "true"},
			Annotations:     map[string]string{netadapter.AnnotationCiliumIPPool: "paguro-10-250-0-9"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "web-5d", UID: ownerUID, Controller: ptr.To(true)}},
		},
		Spec: corev1.PodSpec{
			NodeName: "node-a",
			InitContainers: []corev1.Container{
				{Name: "migrate-db", Image: "busybox"},
				{Name: "envoy", Image: "envoy", RestartPolicy: &always},
				{Name: "chown", Image: "busybox"},
			},
			Containers:      []corev1.Container{{Name: "app", Image: "nginx"}},
			SchedulingGates: []corev1.PodSchedulingGate{{Name: "x"}},
		},
	}
}

func migration(adapter string, preserved bool) *v1alpha1.Migration {
	src, _ := EncodeSourcePod(sourcePod())
	return &v1alpha1.Migration{
		ObjectMeta: metav1.ObjectMeta{Name: "web-abc-x1", Namespace: "shop", UID: "mig-uid",
			Annotations: map[string]string{AnnotationSourcePod: src}},
		Spec: v1alpha1.MigrationSpec{PodName: "web-abc"},
		Status: v1alpha1.MigrationStatus{
			Phase: v1alpha1.PhaseCuttingOver, TargetNode: "node-b", SourcePodIP: "10.250.0.9",
			NetworkAdapter: adapter, IPPreserved: preserved,
		},
	}
}

// replacement simulates the new pod created by the ReplicaSet controller.
func replacement() *corev1.Pod {
	p := sourcePod()
	p.Name, p.UID, p.Spec.NodeName = "", "", ""
	p.GenerateName = "web-5d-"
	p.Annotations = nil
	return p
}

func TestMutateIntoRestoreTargetCommon(t *testing.T) {
	pod := replacement()
	if err := MutateIntoRestoreTarget(pod, migration(netadapter.NameGeneric, false), netadapter.Generic{}); err != nil {
		t.Fatal(err)
	}
	if pod.Spec.NodeName != "node-b" || pod.Spec.RuntimeClassName == nil || *pod.Spec.RuntimeClassName != "paguro" {
		t.Errorf("nodeName/runtimeClass not set: %q %v", pod.Spec.NodeName, pod.Spec.RuntimeClassName)
	}
	if pod.Spec.SchedulingGates != nil {
		t.Error("scheduling gates must be removed (incompatible with nodeName)")
	}
	want := map[string]string{
		v1alpha1.AnnotationRestore:     "web-abc-x1",
		v1alpha1.AnnotationRestoreID:   "mig-uid",
		v1alpha1.AnnotationTCP:         "close",
		v1alpha1.AnnotationOldIP:       "10.250.0.9",
		v1alpha1.AnnotationSkippedInit: `["migrate-db","chown"]`,
	}
	for k, v := range want {
		if pod.Annotations[k] != v {
			t.Errorf("annotation %s = %q, want %q", k, pod.Annotations[k], v)
		}
	}
	if len(pod.Spec.InitContainers) != 1 || pod.Spec.InitContainers[0].Name != "envoy" {
		t.Errorf("only the sidecar must remain, got %v", pod.Spec.InitContainers)
	}
	if _, ok := pod.Annotations[netadapter.AnnotationCiliumIPPool]; ok {
		t.Error("generic adapter must not set a cilium pool")
	}
}

// With fsGroup, kubelet would change the mode of every file on the volumes
// again when it mounts them for the replacement – CRIU then refuses mapped
// files. The replacement only checks the root (an explicit policy stays).
func TestRestoreTargetKeepsFileModes(t *testing.T) {
	gid := int64(1000)
	pod := replacement()
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &gid}
	if err := MutateIntoRestoreTarget(pod, migration(netadapter.NameGeneric, false), netadapter.Generic{}); err != nil {
		t.Fatal(err)
	}
	if p := pod.Spec.SecurityContext.FSGroupChangePolicy; p == nil || *p != corev1.FSGroupChangeOnRootMismatch {
		t.Fatalf("policy %v", p)
	}
	always := corev1.FSGroupChangeAlways
	pod = replacement()
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &gid, FSGroupChangePolicy: &always}
	_ = MutateIntoRestoreTarget(pod, migration(netadapter.NameGeneric, false), netadapter.Generic{})
	if *pod.Spec.SecurityContext.FSGroupChangePolicy != corev1.FSGroupChangeAlways {
		t.Fatal("an explicit policy must stay")
	}
}

func TestMutateIntoRestoreTargetPerAdapter(t *testing.T) {
	cases := []struct {
		adapter   netadapter.Adapter
		preserved bool
		key, want string
		tcp       string
	}{
		{netadapter.Calico{}, true, netadapter.AnnotationCalicoIPAddrs, `["10.250.0.9"]`, "established"},
		{netadapter.Cilium{}, true, netadapter.AnnotationCiliumIPPool, "paguro-10-250-0-9", "established"},
		{netadapter.Cilium{}, false, netadapter.AnnotationCiliumIPPool, "", "close"},
		{netadapter.Generic{}, false, netadapter.AnnotationCalicoIPAddrs, "", "close"},
	}
	for _, tt := range cases {
		t.Run(tt.adapter.Name(), func(t *testing.T) {
			pod := replacement()
			if err := MutateIntoRestoreTarget(pod, migration(tt.adapter.Name(), tt.preserved), tt.adapter); err != nil {
				t.Fatal(err)
			}
			if got := pod.Annotations[tt.key]; got != tt.want {
				t.Errorf("%s = %q, want %q", tt.key, got, tt.want)
			}
			if got := pod.Annotations[v1alpha1.AnnotationTCP]; got != tt.tcp {
				t.Errorf("tcp = %q, want %q", got, tt.tcp)
			}
		})
	}
}

func TestMutateWithoutInitContainersHasNoSkippedAnnotation(t *testing.T) {
	pod := replacement()
	pod.Spec.InitContainers = nil
	if err := MutateIntoRestoreTarget(pod, migration("generic", false), netadapter.Generic{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := pod.Annotations[v1alpha1.AnnotationSkippedInit]; ok {
		t.Error("no skipped-init annotation expected")
	}
}

func TestBareReplacement(t *testing.T) {
	src := sourcePod()
	src.OwnerReferences = nil
	src.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug"}}}
	mig := migration(netadapter.NameCilium, true)
	mig.Annotations[AnnotationSourcePod], _ = EncodeSourcePod(src)
	pod, err := BareReplacement(mig, netadapter.Cilium{})
	if err != nil {
		t.Fatal(err)
	}
	if pod.Name != "web-abc" || pod.Namespace != "shop" || pod.UID != "" || pod.Spec.NodeName != "node-b" {
		t.Errorf("unexpected identity: %s/%s uid=%q node=%s", pod.Namespace, pod.Name, pod.UID, pod.Spec.NodeName)
	}
	if pod.Spec.EphemeralContainers != nil {
		t.Error("ephemeral containers must be dropped")
	}
	if pod.Annotations[netadapter.AnnotationCiliumIPPool] != "paguro-10-250-0-9" || pod.Labels["app"] != "web" {
		t.Errorf("metadata not carried over: %v %v", pod.Annotations, pod.Labels)
	}
}

type fixedAlloc struct{ calls int }

func (f *fixedAlloc) Allocate(context.Context) (string, netip.Addr, error) {
	f.calls++
	return "paguro-10-250-0-42", netip.MustParseAddr("10.250.0.42"), nil
}

func request(t *testing.T, pod *corev1.Pod, dryRun bool) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID: "req", Operation: admissionv1.Create, Namespace: "shop",
		Kind:   metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
		Object: runtime.RawExtension{Raw: raw}, DryRun: &dryRun,
	}}
}

func applyPatch(t *testing.T, pod *corev1.Pod, resp admission.Response) *corev1.Pod {
	t.Helper()
	if !resp.Allowed {
		t.Fatalf("denied: %v", resp.Result)
	}
	raw, _ := json.Marshal(pod)
	ops, _ := json.Marshal(resp.Patches)
	patch, err := jsonpatchv5.DecodePatch(ops)
	if err != nil {
		t.Fatal(err)
	}
	out, err := patch.Apply(raw)
	if err != nil {
		t.Fatal(err)
	}
	var res corev1.Pod
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	return &res
}

func TestHandlerInterceptsExactlyOnce(t *testing.T) {
	reg := NewRegistry()
	mig := migration(netadapter.NameCalico, true)
	reg.Register(context.Background(), withOwner(mig), false)
	h := &PodMutator{Registry: reg, ClusterAdapter: func() netadapter.Adapter { return netadapter.Calico{} }}

	// Dry run consumes nothing.
	resp := h.Handle(context.Background(), request(t, replacement(), true))
	if len(resp.Patches) == 0 {
		t.Fatal("dry run should still show the mutation")
	}
	if _, ok := reg.Pending(context.Background(), ownerUID); !ok {
		t.Fatal("dry run must not consume")
	}

	resp = h.Handle(context.Background(), request(t, replacement(), false))
	got := applyPatch(t, replacement(), resp)
	if got.Spec.NodeName != "node-b" || got.Annotations[netadapter.AnnotationCalicoIPAddrs] != `["10.250.0.9"]` {
		t.Fatalf("not mutated: node=%q ann=%v", got.Spec.NodeName, got.Annotations)
	}
	if _, ok := reg.ConsumedAt(mig); !ok {
		t.Error("consumption time not recorded")
	}

	// A second pod of the same owner (e.g. scale-up) does NOT become a restore
	// target. As a migratable pod it only gets the RuntimeClass "paguro"
	// (time namespace), nothing else.
	resp = h.Handle(context.Background(), request(t, replacement(), false))
	second := applyPatch(t, replacement(), resp)
	if second.Spec.NodeName != "" || second.Annotations[v1alpha1.AnnotationRestoreID] != "" {
		t.Errorf("second pod must not become a restore target: node=%q ann=%v", second.Spec.NodeName, second.Annotations)
	}
	for _, p := range resp.Patches {
		if p.Path != "/spec/runtimeClassName" {
			t.Errorf("unexpected patch on second pod: %v", p)
		}
	}

	// Register after consumption without force has no effect (restart path).
	reg.Register(context.Background(), withOwner(mig), false)
	if _, ok := reg.Pending(context.Background(), ownerUID); ok {
		t.Error("consumed migration must not be re-registered without force")
	}
	reg.Register(context.Background(), withOwner(mig), true)
	if _, ok := reg.Pending(context.Background(), ownerUID); !ok {
		t.Error("force re-register must work")
	}
	reg.Forget(context.Background(), mig)
	if _, ok := reg.Pending(context.Background(), ownerUID); ok {
		t.Error("Forget must remove pending entry")
	}
}

func TestHandlerStickyIP(t *testing.T) {
	alloc := &fixedAlloc{}
	h := &PodMutator{Registry: NewRegistry(), Sticky: alloc,
		ClusterAdapter: func() netadapter.Adapter { return netadapter.Cilium{} }}

	pod := replacement()
	resp := h.Handle(context.Background(), request(t, pod, false))
	got := applyPatch(t, pod, resp)
	if got.Annotations[netadapter.AnnotationCiliumIPPool] != "paguro-10-250-0-42" ||
		got.Annotations[v1alpha1.AnnotationStickyIP] != "paguro-10-250-0-42" {
		t.Fatalf("sticky annotations missing: %v", got.Annotations)
	}

	// Dry run, not migratable, preset pool, restore target: no allocation.
	alloc.calls = 0
	dry := replacement()
	h.Handle(context.Background(), request(t, dry, true))
	plain := replacement()
	plain.Labels = nil
	h.Handle(context.Background(), request(t, plain, false))
	preset := replacement()
	preset.Annotations = map[string]string{netadapter.AnnotationCiliumIPPool: "team-pool"}
	h.Handle(context.Background(), request(t, preset, false))
	// Migrations of this pod change its IP: no sticky IP, but the RuntimeClass.
	ph := replacement()
	ph.Annotations = map[string]string{v1alpha1.AnnotationNetwork: "Phantom"}
	if got := applyPatch(t, ph, h.Handle(context.Background(), request(t, ph, false))); got.Spec.RuntimeClassName == nil {
		t.Error("a Phantom-mode pod still needs the RuntimeClass")
	}
	restore := replacement()
	restore.OwnerReferences = nil
	restore.Annotations = map[string]string{v1alpha1.AnnotationRestoreID: "x"}
	h.Handle(context.Background(), request(t, restore, false))
	if alloc.calls != 0 {
		t.Errorf("allocator called %d times, want 0", alloc.calls)
	}

	// Calico needs no sticky IP.
	h.ClusterAdapter = func() netadapter.Adapter { return netadapter.Calico{} }
	h.Handle(context.Background(), request(t, replacement(), false))
	if alloc.calls != 0 {
		t.Error("calico must not allocate")
	}
}

// An unknown paguro.dev/network value denies the pod instead of reading as
// Auto: under Cilium, Auto means a sticky IP, which rules out Phantom mode
// for the pod's lifetime – also when the value was a misspelt "phantom".
func TestHandlerRejectsUnknownNetworkMode(t *testing.T) {
	alloc := &fixedAlloc{}
	h := &PodMutator{Registry: NewRegistry(), Sticky: alloc,
		ClusterAdapter: func() netadapter.Adapter { return netadapter.Cilium{} }}
	for _, c := range []struct{ value, want string }{
		{"phantm", `annotation paguro.dev/network: unknown network mode "phantm" (want auto, preserve, phantom or generic)`},
		{"keep-ip", `unknown network mode "keep-ip"`},
	} {
		for _, dryRun := range []bool{false, true} {
			pod := replacement()
			pod.Annotations = map[string]string{v1alpha1.AnnotationNetwork: c.value}
			resp := h.Handle(context.Background(), request(t, pod, dryRun))
			if resp.Allowed || resp.Result == nil || !strings.Contains(resp.Result.Message, c.want) {
				t.Errorf("%q (dry run %v): allowed=%v result=%v, want denied with %q", c.value, dryRun, resp.Allowed, resp.Result, c.want)
			}
		}
	}
	if alloc.calls != 0 {
		t.Errorf("allocator called %d times for denied pods", alloc.calls)
	}

	// Not migratable: the annotation means nothing to Paguro.
	plain := replacement()
	plain.Labels = nil
	plain.Annotations = map[string]string{v1alpha1.AnnotationNetwork: "phantm"}
	if resp := h.Handle(context.Background(), request(t, plain, false)); !resp.Allowed {
		t.Errorf("a pod that is not migratable must be admitted: %v", resp.Result)
	}

	// Valid values in any case are admitted; generic gets no sticky IP.
	for _, v := range []string{"auto", "Preserve", "PHANTOM", "generic"} {
		pod := replacement()
		pod.Annotations = map[string]string{v1alpha1.AnnotationNetwork: v}
		got := applyPatch(t, pod, h.Handle(context.Background(), request(t, pod, false)))
		sticky := got.Annotations[v1alpha1.AnnotationStickyIP] != ""
		if wantSticky := v == "auto" || v == "Preserve"; sticky != wantSticky {
			t.Errorf("%q: sticky IP %v, want %v", v, sticky, wantSticky)
		}
	}
}

// busyAlloc blocks like an allocator whose lock a rotation holds.
type busyAlloc struct{}

func (busyAlloc) Allocate(ctx context.Context) (string, netip.Addr, error) {
	<-ctx.Done()
	return "", netip.Addr{}, ctx.Err()
}

// A slow allocation must not cost the pod its RuntimeClass: past the API
// server's timeout the pod would be admitted unmutated.
func TestHandlerStickyBusy(t *testing.T) {
	defer func(d time.Duration) { stickyBudget = d }(stickyBudget)
	stickyBudget = 50 * time.Millisecond
	h := &PodMutator{Registry: NewRegistry(), Sticky: busyAlloc{},
		ClusterAdapter: func() netadapter.Adapter { return netadapter.Cilium{} }}
	pod := replacement()
	start := time.Now()
	resp := h.Handle(context.Background(), request(t, pod, false))
	if d := time.Since(start); d > time.Second {
		t.Fatalf("handler took %s", d)
	}
	got := applyPatch(t, pod, resp)
	if got.Spec.RuntimeClassName == nil || *got.Spec.RuntimeClassName != v1alpha1.RuntimeClassName {
		t.Fatalf("RuntimeClass missing: %v", got.Spec.RuntimeClassName)
	}
	if got.Annotations[netadapter.AnnotationCiliumIPPool] != "" || len(resp.Warnings) == 0 {
		t.Fatalf("want no pool and a warning: %v %v", got.Annotations, resp.Warnings)
	}
}

func TestCertManager(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	cfg := &admissionregistrationv1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "paguro"},
		Webhooks:   []admissionregistrationv1.MutatingWebhook{{Name: "pods.paguro.dev"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cfg).Build()
	dir := t.TempDir()
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	cm := &CertManager{Client: c, Namespace: "paguro-system", SecretName: "paguro-webhook-tls",
		ServiceName: "paguro-controller", WebhookConfigName: "paguro", CertDir: dir, Now: func() time.Time { return now }}
	if err := cm.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	var sec corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "paguro-system", Name: "paguro-webhook-tls"}, &sec); err != nil {
		t.Fatal(err)
	}
	if !cm.keeper().Valid(sec.Data) {
		t.Fatal("generated certificate does not validate")
	}
	if b, err := os.ReadFile(filepath.Join(dir, "tls.crt")); err != nil || len(b) == 0 {
		t.Fatal("tls.crt not written")
	}
	_ = c.Get(context.Background(), types.NamespacedName{Name: "paguro"}, cfg)
	if string(cfg.Webhooks[0].ClientConfig.CABundle) != string(sec.Data["ca.crt"]) {
		t.Fatal("caBundle not patched")
	}

	// Second run: secret stays the same (restart keeps the certificate).
	before := string(sec.Data["tls.crt"])
	if err := cm.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "paguro-system", Name: "paguro-webhook-tls"}, &sec)
	if string(sec.Data["tls.crt"]) != before {
		t.Fatal("valid certificate must be reused")
	}

	// Shortly before expiry: new serving certificate, CA stays.
	ca := string(sec.Data["ca.crt"])
	now = now.Add(servingValidity - 30*24*time.Hour)
	if err := cm.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "paguro-system", Name: "paguro-webhook-tls"}, &sec)
	if string(sec.Data["tls.crt"]) == before || string(sec.Data["ca.crt"]) != ca {
		t.Fatal("expected renewed serving cert with same CA")
	}
}

func TestCiliumReplacementGetsNewPoolGeneration(t *testing.T) {
	mig := migration(netadapter.NameCilium, true)
	mig.Status.Network = v1alpha1.NetworkStatus{SourcePool: "paguro-10-250-0-9", TargetPool: "paguro-10-250-0-9-migui"}
	pod := replacement()
	if err := MutateIntoRestoreTarget(pod, mig, netadapter.Cilium{}); err != nil {
		t.Fatal(err)
	}
	if pod.Annotations[netadapter.AnnotationCiliumIPPool] != "paguro-10-250-0-9-migui" ||
		pod.Annotations[v1alpha1.AnnotationStickyIP] != "paguro-10-250-0-9-migui" {
		t.Errorf("want new generation pool, got %v", pod.Annotations)
	}
}

// Bare-pod replacements copy the source's annotations, including Calico's
// per-sandbox state. It must be gone in every network mode.
func TestBareReplacementDropsCalicoPodState(t *testing.T) {
	for _, tt := range []struct {
		adapter   netadapter.Adapter
		preserved bool
		ipAddrs   string
	}{
		{netadapter.Calico{}, true, `["10.250.0.9"]`},
		{netadapter.Generic{}, false, ""},
	} {
		src := sourcePod()
		src.OwnerReferences = nil
		src.Annotations = map[string]string{
			netadapter.AnnotationCalicoPodIP:       "10.250.0.9/32",
			netadapter.AnnotationCalicoPodIPs:      "10.250.0.9/32",
			netadapter.AnnotationCalicoContainerID: "src-sandbox",
			"app.example/keep":                     "yes",
		}
		mig := migration(tt.adapter.Name(), tt.preserved)
		mig.Annotations[AnnotationSourcePod], _ = EncodeSourcePod(src)
		pod, err := BareReplacement(mig, tt.adapter)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{netadapter.AnnotationCalicoPodIP, netadapter.AnnotationCalicoPodIPs, netadapter.AnnotationCalicoContainerID} {
			if _, ok := pod.Annotations[k]; ok {
				t.Errorf("%s: stale annotation %s kept", tt.adapter.Name(), k)
			}
		}
		if pod.Annotations[netadapter.AnnotationCalicoIPAddrs] != tt.ipAddrs || pod.Annotations["app.example/keep"] != "yes" {
			t.Errorf("%s: unexpected annotations %v", tt.adapter.Name(), pod.Annotations)
		}
	}
}

// withOwner sets the migration's replacement owner to ownerUID.
func withOwner(m *v1alpha1.Migration) *v1alpha1.Migration {
	m.Status.Cutover.ReplacementOwnerUID = string(ownerUID)
	return m
}

func TestHandlerStampsCPUBaseline(t *testing.T) {
	calls := 0
	h := &PodMutator{Registry: NewRegistry(), CPUBaseline: func(context.Context) (string, error) {
		calls++
		return "avx2,sse2", nil
	}}
	got := applyPatch(t, replacement(), h.Handle(context.Background(), request(t, replacement(), false)))
	if got.Annotations[v1alpha1.AnnotationCPUBaseline] != "avx2,sse2" {
		t.Fatalf("baseline not stamped: %v", got.Annotations)
	}
	// An explicit baseline (or one from an earlier start) stays.
	own := replacement()
	own.Annotations = map[string]string{v1alpha1.AnnotationCPUBaseline: "sse2"}
	got = applyPatch(t, own, h.Handle(context.Background(), request(t, own, false)))
	if got.Annotations[v1alpha1.AnnotationCPUBaseline] != "sse2" {
		t.Fatalf("explicit baseline replaced: %v", got.Annotations)
	}
	// Not migratable: nothing.
	plain := replacement()
	plain.Labels = nil
	calls = 0
	h.Handle(context.Background(), request(t, plain, false))
	if calls != 0 {
		t.Error("baseline computed for a pod that is not migratable")
	}
}

// The replacement continues the source's processes: it keeps their baseline.
func TestRestoreTargetKeepsCPUBaseline(t *testing.T) {
	mig := migration(netadapter.NameGeneric, false)
	src := sourcePod()
	src.Annotations = map[string]string{v1alpha1.AnnotationCPUBaseline: "avx2,sse2"}
	mig.Annotations[AnnotationSourcePod], _ = EncodeSourcePod(src)
	pod := replacement()
	if err := MutateIntoRestoreTarget(pod, mig, netadapter.Generic{}); err != nil {
		t.Fatal(err)
	}
	if pod.Annotations[v1alpha1.AnnotationCPUBaseline] != "avx2,sse2" {
		t.Fatalf("baseline lost: %v", pod.Annotations)
	}
}

// The replacement runs exactly the images the source node ran, not what the
// tag means on the target node today (internal/images).
func TestRestoreTargetPinsImages(t *testing.T) {
	mig := migration(netadapter.NameGeneric, false)
	src := sourcePod()
	src.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app", Image: "docker.io/library/nginx:latest", ImageID: "docker.io/library/nginx@sha256:aa"}}
	src.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "envoy", ImageID: "docker.io/library/envoy@sha256:bb"}}
	mig.Annotations[AnnotationSourcePod], _ = EncodeSourcePod(src)
	pod := replacement()
	if err := MutateIntoRestoreTarget(pod, mig, netadapter.Generic{}); err != nil {
		t.Fatal(err)
	}
	if got := pod.Spec.Containers[0].Image; got != "nginx@sha256:aa" {
		t.Errorf("app image %q", got)
	}
	// The digest was pulled during pre-copy: no registry round trip in the freeze.
	if got := pod.Spec.Containers[0].ImagePullPolicy; got != corev1.PullIfNotPresent {
		t.Errorf("pull policy %q, want IfNotPresent", got)
	}
	for _, c := range pod.Spec.InitContainers {
		if c.Name == "envoy" && c.Image != "envoy@sha256:bb" {
			t.Errorf("sidecar image %q", c.Image)
		}
	}
}

// Kept IP on Cilium, created before the commit: held back by the commit gate,
// not bound, and out of reach of every scheduler – without anything that
// would restrict the running pod's next migration.
func TestRestoreTargetGatedUntilCommit(t *testing.T) {
	mig := migration(netadapter.NameCilium, true)
	mig.Status.Network.TargetPool = "paguro-10-250-0-9-migui"
	mig.Status.Phase = v1alpha1.PhasePreCopy
	pod := replacement()
	if err := MutateIntoRestoreTarget(pod, mig, netadapter.Cilium{}); err != nil {
		t.Fatal(err)
	}
	if pod.Spec.NodeName != "" {
		t.Errorf("gated replacement must not be bound: nodeName %q", pod.Spec.NodeName)
	}
	if len(pod.Spec.SchedulingGates) != 1 || pod.Spec.SchedulingGates[0].Name != v1alpha1.SchedulingGateCommit {
		t.Errorf("gates %+v", pod.Spec.SchedulingGates)
	}
	if pod.Spec.SchedulerName != v1alpha1.SchedulerNameBind {
		t.Errorf("schedulerName %q", pod.Spec.SchedulerName)
	}
	if pod.Spec.Affinity != nil {
		t.Errorf("no affinity may be added: %+v", pod.Spec.Affinity)
	}

	// Created after the commit: bound directly, no gate.
	mig.Status.Phase = v1alpha1.PhaseCuttingOver
	pod = replacement()
	if err := MutateIntoRestoreTarget(pod, mig, netadapter.Cilium{}); err != nil {
		t.Fatal(err)
	}
	if pod.Spec.NodeName != "node-b" || len(pod.Spec.SchedulingGates) != 0 {
		t.Errorf("after the commit: nodeName %q gates %+v", pod.Spec.NodeName, pod.Spec.SchedulingGates)
	}
}

// With the commit gate the gated replacement references its migration's
// gate claim – and only that one, not an earlier migration's.
func TestRestoreTargetGetsGateClaim(t *testing.T) {
	mig := migration(netadapter.NameCilium, true)
	mig.Status.Network.TargetPool = "paguro-10-250-0-9-migui"
	mig.Status.Network.CommitGate = true
	mig.Status.Phase = v1alpha1.PhasePreCopy
	pod := replacement()
	pod.Spec.ResourceClaims = []corev1.PodResourceClaim{{Name: names.GateClaim, ResourceClaimName: ptr.To("paguro-gate-older")}}
	if err := MutateIntoRestoreTarget(pod, mig, netadapter.Cilium{}); err != nil {
		t.Fatal(err)
	}
	if len(pod.Spec.ResourceClaims) != 1 || *pod.Spec.ResourceClaims[0].ResourceClaimName != gate.ClaimName(mig.UID) {
		t.Fatalf("claims %+v", pod.Spec.ResourceClaims)
	}
}
