// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// paguro-controller: orchestration of migrations and the admission webhook.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	crwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/agentca"
	"paguro.dev/paguro/internal/controller"
	"paguro.dev/paguro/internal/netadapter"
	"paguro.dev/paguro/internal/pki"
	"paguro.dev/paguro/internal/webhook"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

type options struct {
	metricsAddr, probeAddr string
	webhookPort            int
	leaderElect            bool
	namespace              string
	webhookExclude         string
	serviceName            string
	webhookConfig          string
	webhookSecret          string
	agentCA                string
	shutdownDelay          time.Duration
	certDir                string
	stickyCIDR             string
	phantomAuto            bool
	commitGate             bool
	earlyHandOver          bool
	phantomCIDRs           string
	cpuBaseline            string
	migrationsPerNode      int
	evictionTargetWait     time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.metricsAddr, "metrics-bind-address", ":8080", "Address of the Prometheus endpoint")
	flag.StringVar(&o.probeAddr, "health-probe-bind-address", ":8081", "Address for /healthz and /readyz")
	flag.IntVar(&o.webhookPort, "webhook-port", 9443, "Port of the admission webhook")
	flag.BoolVar(&o.leaderElect, "leader-elect", true, "Enable leader election")
	flag.StringVar(&o.namespace, "namespace", envOr("POD_NAMESPACE", "paguro-system"), "Namespace of the controller")
	flag.StringVar(&o.webhookExclude, "webhook-exclude-namespaces", "kube-system",
		"Namespaces the pod webhook does not see (comma-separated; the controller's own is added)")
	flag.StringVar(&o.serviceName, "service-name", "paguro-controller", "Service in front of the webhook (for the certificate)")
	flag.StringVar(&o.webhookConfig, "webhook-config", "paguro", "Name of the MutatingWebhookConfiguration")
	flag.StringVar(&o.webhookSecret, "webhook-secret", "paguro-webhook-tls", "Secret for the CA and serving certificate")
	flag.StringVar(&o.agentCA, "agent-ca", "paguro-agent-ca",
		"Secret (CA) and ConfigMap (its certificate) for the agents' node certificates – mutual TLS between agents, "+
			"signer "+agentca.SignerName+"; empty: no signer")
	flag.DurationVar(&o.shutdownDelay, "shutdown-delay", 5*time.Second,
		"keep serving this long after SIGTERM (the endpoint leaves the webhook's Service meanwhile)")
	flag.StringVar(&o.certDir, "cert-dir", "/tmp/k8s-webhook-server/serving-certs", "Directory for tls.crt/tls.key")
	flag.StringVar(&o.stickyCIDR, "sticky-cidr", "10.250.0.0/16", "IPv4 range for sticky IPs (Cilium)")
	flag.BoolVar(&o.phantomAuto, "phantom-auto", true, "network=Auto falls back to Phantom mode when the IP cannot be kept and every node supports it")
	flag.BoolVar(&o.commitGate, "commit-gate", true, "replacements that keep the IP wait at the commit gate (DRA) on the target node; needs resource.k8s.io/v1")
	flag.IntVar(&o.migrationsPerNode, "migrations-per-node", 3, "migrations that move pods off one node at a time; further ones wait in Pending (0: no bound)")
	flag.DurationVar(&o.evictionTargetWait, "eviction-target-wait", 2*time.Minute, "how long a migration that an eviction started waits for a node to move to, e.g. one Karpenter is launching (0: none)")
	flag.BoolVar(&o.earlyHandOver, "early-handover", true, "with the commit gate on Cilium: create the replacement's sandbox while the final dump runs, not after the commit")
	flag.StringVar(&o.phantomCIDRs, "phantom-cluster-cidrs", "", "comma-separated extra in-cluster prefixes for Phantom mode")
	flag.StringVar(&o.cpuBaseline, "cpu-baseline", "auto", "CPU features new migratable pods may use: auto (shared by all nodes) | x86-64-v1 … x86-64-v4 | off")
	zapOpts := zap.Options{}
	zapOpts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))

	if err := run(shutdownAfter(o.shutdownDelay), o); err != nil {
		ctrl.Log.Error(err, "paguro-controller exited")
		os.Exit(1)
	}
}

func run(ctx context.Context, o options) error {
	log := ctrl.Log.WithName("setup")
	log.Info("starting paguro-controller", "version", version)
	scheme, err := newScheme()
	if err != nil {
		return err
	}
	cfg := ctrl.GetConfigOrDie()

	// Provision the certificates before the webhook server starts.
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	certs, signer, err := provisionCertificates(ctx, direct, o)
	if err != nil {
		return err
	}
	mgr, err := newManager(cfg, scheme, o)
	if err != nil {
		return err
	}
	detected, err := detectNetwork(ctx, mgr)
	if err != nil {
		return err
	}
	adapter := func() netadapter.Adapter { return detected }
	registry, pools, err := setupWebhooks(ctx, cfg, mgr, o, detected, adapter)
	if err != nil {
		return err
	}
	metrics.Registry.MustRegister(&controller.ActiveCollector{Reader: mgr.GetClient()})
	if err := addCertificates(mgr, certs, signer); err != nil {
		return err
	}
	rec := newReconciler(mgr, o, registry, adapter, pools)
	if err := rec.SetupWithManager(mgr); err != nil {
		return err
	}
	if err := mgr.Add(newAudit(mgr, rec, o)); err != nil {
		return err
	}
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("webhook", mgr.GetWebhookServer().StartedChecker()); err != nil {
		return err
	}
	log.Info("starting manager")
	return mgr.Start(ctx)
}

func newScheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return scheme, v1alpha1.AddToScheme(scheme)
}

func newManager(cfg *rest.Config, scheme *runtime.Scheme, o options) (ctrl.Manager, error) {
	return ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       metricsserver.Options{BindAddress: o.metricsAddr},
		HealthProbeBindAddress:        o.probeAddr,
		LeaderElection:                o.leaderElect,
		LeaderElectionID:              "paguro-controller.paguro.dev",
		LeaderElectionNamespace:       o.namespace,
		LeaderElectionReleaseOnCancel: true,
		WebhookServer:                 crwebhook.NewServer(crwebhook.Options{Port: o.webhookPort, CertDir: o.certDir}),
		Cache:                         cache.Options{DefaultTransform: cache.TransformStripManagedFields()},
	})
}

// detectNetwork detects the CNI once at startup; a change is only reported.
func detectNetwork(ctx context.Context, mgr ctrl.Manager) (netadapter.Adapter, error) {
	detected, err := netadapter.Detect(ctx, mgr.GetAPIReader())
	if err != nil {
		return nil, err
	}
	ctrl.Log.WithName("setup").Info("detected network adapter", "adapter", detected.Name())
	return detected, mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		watchCNIChange(ctx, mgr.GetAPIReader(), detected)
		return nil
	}))
}

// setupWebhooks registers the pod mutator and the eviction webhook. The
// interception state lives in the Migration objects: every replica's
// webhook can intercept a replacement pod, exactly one does.
func setupWebhooks(ctx context.Context, cfg *rest.Config, mgr ctrl.Manager, o options, detected netadapter.Adapter,
	adapter func() netadapter.Adapter) (*webhook.APIRegistry, controller.PoolRotator, error) {
	if err := webhook.IndexOwner(ctx, mgr.GetFieldIndexer()); err != nil {
		return nil, nil, err
	}
	registry := &webhook.APIRegistry{Client: mgr.GetClient(), Reader: mgr.GetAPIReader()}
	baseline, err := controller.CPUBaseline(mgr.GetClient(), o.cpuBaseline)
	if err != nil {
		return nil, nil, err
	}
	mutator := &webhook.PodMutator{Registry: registry, ClusterAdapter: adapter, CPUBaseline: baseline}
	var pools controller.PoolRotator
	if detected.NeedsStickyIP() {
		if pools, err = setupStickyIPs(cfg, mgr, mutator, o.stickyCIDR); err != nil {
			return nil, nil, err
		}
	}
	mgr.GetWebhookServer().Register(webhook.PodMutatePath, &admission.Webhook{Handler: mutator})
	mgr.GetWebhookServer().Register(webhook.EvictionPath, &admission.Webhook{Handler: &webhook.EvictionHandler{
		Client: mgr.GetClient(), Reader: mgr.GetAPIReader()}})
	return registry, pools, nil
}

// addCertificates runs the webhook certificate's renewal and, if enabled,
// the agents' certificate signer.
func addCertificates(mgr ctrl.Manager, certs *webhook.CertManager, signer *agentca.Signer) error {
	if err := mgr.Add(certs); err != nil {
		return err
	}
	if signer == nil {
		return nil
	}
	// The signer keeps the uncached client: the manager may not cache
	// Secrets (RBAC allows only its own by name).
	if err := signer.SetupWithManager(mgr); err != nil {
		return err
	}
	return mgr.Add(signer)
}

func newReconciler(mgr ctrl.Manager, o options, registry *webhook.APIRegistry, adapter func() netadapter.Adapter,
	pools controller.PoolRotator) *controller.MigrationReconciler {
	rec := &controller.MigrationReconciler{
		Client:             mgr.GetClient(),
		APIReader:          mgr.GetAPIReader(),
		Recorder:           mgr.GetEventRecorder("paguro-controller"),
		Registry:           registry,
		Adapter:            adapter,
		Metrics:            controller.DefaultMetrics(),
		Clock:              clock.RealClock{},
		Pools:              pools,
		PhantomAuto:        o.phantomAuto,
		CommitGate:         o.commitGate && hasResourceAPI(mgr),
		PerNode:            o.migrationsPerNode,
		EvictionTargetWait: o.evictionTargetWait,
	}
	rec.EarlyHandOver = rec.CommitGate && o.earlyHandOver
	for _, c := range strings.Split(o.phantomCIDRs, ",") {
		if c = strings.TrimSpace(c); c != "" {
			rec.PhantomExtraCIDRs = append(rec.PhantomExtraCIDRs, c)
		}
	}
	return rec
}

// provisionCertificates creates or renews the webhook's serving
// certificate and, unless disabled, publishes the agents' CA: agents wait
// for its bundle before they accept migrations.
func provisionCertificates(ctx context.Context, direct client.Client, o options) (*webhook.CertManager, *agentca.Signer, error) {
	certs := &webhook.CertManager{
		Client: direct, Namespace: o.namespace, SecretName: o.webhookSecret,
		ServiceName: o.serviceName, WebhookConfigName: o.webhookConfig, CertDir: o.certDir,
	}
	if err := certs.Ensure(ctx); err != nil {
		return nil, nil, err
	}
	if o.agentCA == "" {
		return certs, nil, nil
	}
	signer := &agentca.Signer{
		Client:    direct,
		CA:        &pki.SecretKeeper{Client: direct, Namespace: o.namespace, Name: o.agentCA, CAName: "paguro-agent-ca"},
		AgentUser: "system:serviceaccount:" + o.namespace + ":paguro-agent",
		Bundle:    types.NamespacedName{Namespace: o.namespace, Name: o.agentCA},
	}
	if err := signer.Publish(ctx); err != nil {
		return nil, nil, err
	}
	return certs, signer, nil
}

// setupStickyIPs wires the sticky IPs of a CNI that needs them (Cilium's
// multi-pool IPAM): the allocator for the webhook, the pool rotation for
// the controller and the garbage collection of unused pools.
func setupStickyIPs(cfg *rest.Config, mgr ctrl.Manager, mutator *webhook.PodMutator, cidr string) (controller.PoolRotator, error) {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	disc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, err
	}
	store := &netadapter.CiliumPoolStore{Dynamic: dyn, Discovery: disc}
	alloc, err := netadapter.NewStickyAllocator(cidr, store)
	if err != nil {
		return nil, err
	}
	// Another replica may be rotating a pool generation right now (old
	// pool deleted, new not yet created): the IPs of running migrations
	// are never free.
	alloc.Reserved = controller.MigrationIPs(mgr.GetClient())
	mutator.Sticky = alloc
	err = mgr.Add(&netadapter.PoolGC{
		Store: store, Reader: mgr.GetClient(), Interval: time.Minute, MinAge: 5 * time.Minute,
		InUse: controller.MigrationPools(mgr.GetClient()),
	})
	return &netadapter.CiliumRotator{Allocator: alloc, Store: store}, err
}

// newAudit checks every minute that migratable pods went through the
// webhook, except in the namespaces the webhook does not see.
func newAudit(mgr ctrl.Manager, rec *controller.MigrationReconciler, o options) *controller.MutationAudit {
	audit := &controller.MutationAudit{
		Client: mgr.GetClient(), Recorder: rec.Recorder, Metrics: rec.Metrics, Interval: time.Minute,
		Exclude: map[string]bool{o.namespace: true},
	}
	for _, ns := range strings.Split(o.webhookExclude, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			audit.Exclude[ns] = true
		}
	}
	return audit
}

// watchCNIChange reports when the CNI changes after startup. Sticky IPs
// are only set up for the adapter detected at startup; a change
// requires a controller restart.
func watchCNIChange(ctx context.Context, r client.Reader, current netadapter.Adapter) {
	log := ctrl.Log.WithName("netadapter")
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a, err := netadapter.Detect(ctx, r)
			if err != nil {
				log.Error(err, "re-detecting CNI")
			} else if a.Name() != current.Name() {
				log.Info("CNI changed, restart paguro-controller to apply", "running", current.Name(), "detected", a.Name())
			}
		}
	}
}

// shutdownAfter returns a context that ends delay after the first SIGTERM
// or SIGINT (at once on the second). The controller keeps serving webhook
// requests while its endpoint leaves the Service: without the delay the
// API server reached a replica that had closed its port during a rollout
// (connection refused) and let a pod through unmutated (measured: 1 of 117
// pods in three rollouts). In the process rather than as a preStop sleep,
// which Kubernetes accepts only from 1.30 on.
func shutdownAfter(delay time.Duration) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-ch
		ctrl.Log.Info("shutting down", "servingFor", delay.String())
		select {
		case <-time.After(delay):
		case <-ch:
		}
		cancel()
		<-ch
		os.Exit(1)
	}()
	return ctx
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// hasResourceAPI reports whether the cluster serves resource.k8s.io/v1
// (Dynamic Resource Allocation, GA in Kubernetes 1.34).
func hasResourceAPI(mgr ctrl.Manager) bool {
	dc, err := discovery.NewDiscoveryClientForConfig(mgr.GetConfig())
	if err != nil {
		return false
	}
	_, err = dc.ServerResourcesForGroupVersion("resource.k8s.io/v1")
	return err == nil
}
