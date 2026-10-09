// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// paguro-agent runs as a DaemonSet on every node (privileged, hostPID,
// hostNetwork) and is Paguro's data plane.
package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/agent"
	"paguro.dev/paguro/internal/phantom"
)

// options are the agent's command-line flags.
type options struct {
	port         int
	hostRoot     string
	nsenter      bool
	probeAddr    string
	metricsAddr  string
	ciliumSock   string
	phantomMode  string
	steerMark    uint32
	commitGate   bool
	kubeletDir   string
	testFaults   bool
	preAttach    bool
	version      string
	drainTimeout time.Duration
	caFile       string
}

func parseFlags() options {
	var o options
	flag.IntVar(&o.port, "port", v1.AgentPort, "port for the data transfer")
	flag.StringVar(&o.hostRoot, "host-root", "/proc/1/root", "path to the host root (\"\" when running directly on the host)")
	flag.BoolVar(&o.nsenter, "nsenter", true, "run host programs in the host namespaces via nsenter")
	flag.StringVar(&o.probeAddr, "health-addr", ":9557", "health probes")
	flag.StringVar(&o.metricsAddr, "metrics-addr", ":9556", "Prometheus metrics")
	flag.StringVar(&o.ciliumSock, "cilium-socket", "/var/run/cilium/cilium.sock", "REST socket of the Cilium agent (optional)")
	flag.StringVar(&o.phantomMode, "phantom", "auto", "Phantom mode (new IP, connections kept by eBPF translation): auto | off")
	steerMark := flag.String("phantom-steering-mark", fmt.Sprintf("%#x", phantom.DefaultSteerMark),
		"Phantom mode: the bit of the packet mark that routes forwarded migrated connections to the new address "+
			"(must not be used by the CNI, kube-proxy or anything else on the nodes)")
	flag.BoolVar(&o.commitGate, "commit-gate", true, "register the commit gate (a DRA driver) with kubelet: replacements wait right before their sandbox, not behind kubelet's sync loop")
	flag.StringVar(&o.kubeletDir, "kubelet-dir", "/var/lib/kubelet", "kubelet's data directory as mounted into the agent")
	flag.BoolVar(&o.testFaults, "test-faults", false, "honour the paguro.dev/test-fault annotation (failure tests only)")
	flag.BoolVar(&o.preAttach, "pre-attach", false, "attach RWO volumes to the target during pre-copy (multi-attach volume types only; "+
		"needs create/delete on VolumeAttachments)")
	flag.StringVar(&o.version, "version", "", "the agent's release (image tag), advertised on the node: migrations run only between agents of the same release")
	flag.DurationVar(&o.drainTimeout, "drain-timeout", 10*time.Minute, "on SIGTERM, how long to wait for the migrations on this node to finish (keep it below the pod's terminationGracePeriodSeconds)")
	flag.StringVar(&o.caFile, "transfer-ca", "", "the agents' CA certificate (ConfigMap paguro-agent-ca): the transfer between "+
		"agents runs over mutual TLS with a certificate for this node (signer paguro.dev/agent); empty: plain HTTP")
	flag.Parse()
	// Unknown values are refused (a typo must not enable or disable
	// Phantom mode silently).
	if o.phantomMode != "auto" && o.phantomMode != "off" {
		fmt.Fprintf(os.Stderr, "--phantom: %q is neither auto nor off\n", o.phantomMode)
		os.Exit(2)
	}
	m, err := strconv.ParseUint(*steerMark, 0, 32)
	if err != nil || m == 0 {
		fmt.Fprintf(os.Stderr, "--phantom-steering-mark: %q is not a non-zero 32-bit mark\n", *steerMark)
		os.Exit(2)
	}
	o.steerMark = uint32(m)
	return o
}

func main() {
	o := parseFlags()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.SetLogger(logr.FromSlogHandler(logger.Handler()))
	fatal := func(msg string, err error) {
		logger.Error(msg, "err", err)
		os.Exit(1)
	}

	nodeName := os.Getenv("NODE_NAME")
	token := os.Getenv("PAGURO_TOKEN")
	if nodeName == "" || token == "" {
		fatal("NODE_NAME and PAGURO_TOKEN must be set", nil)
	}
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: o.metricsAddr},
		HealthProbeBindAddress: o.probeAddr,
		// The agent only ever needs the pods of its own node; caching every
		// pod of the cluster in each agent does not scale.
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {Field: fields.OneTermEqualSelector("spec.nodeName", nodeName)},
		}},
	})
	if err != nil {
		fatal("Manager", err)
	}
	clientset, err := kubernetes.NewForConfig(ctrl.GetConfigOrDie())
	if err != nil {
		fatal("Clientset", err)
	}
	a, err := newAgent(o, mgr, scheme, clientset, nodeName, token, logger)
	if err != nil {
		fatal("Agent", err)
	}
	if err := a.SetupWithManager(mgr); err != nil {
		fatal("Reconciler", err)
	}
	_ = mgr.AddHealthzCheck("ping", healthz.Ping)
	_ = mgr.AddReadyzCheck("ping", healthz.Ping)
	_ = mgr.AddReadyzCheck("transfer", func(*http.Request) error {
		if !a.Advertised() {
			return errors.New("transfer endpoint not advertised yet")
		}
		return nil
	})

	ctx := drainOnSignal(a, o.drainTimeout, logger)
	transferUp := serveTransfer(ctx, a, token, logger)
	startBackground(ctx, a, o, clientset, logger)
	go announce(ctx, a, transferUp, logger)
	if err := mgr.Start(ctx); err != nil {
		fatal("manager exited", err)
	}
}

// newAgent builds the agent for this node: its transfer endpoint (the
// node's InternalIP) and the optional parts – mutual TLS, the Cilium
// hooks, Phantom mode – that this node and the flags allow.
func newAgent(o options, mgr ctrl.Manager, scheme *runtime.Scheme, clientset kubernetes.Interface,
	nodeName, token string, logger *slog.Logger) (*agent.Agent, error) {
	// The agent listens on its node's InternalIP and publishes it as its
	// endpoint. The cache does not run yet: read the node directly.
	direct, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}
	ip, err := internalIP(direct, nodeName)
	if err != nil {
		return nil, err
	}
	a := &agent.Agent{
		Client:     mgr.GetClient(),
		APIReader:  mgr.GetAPIReader(),
		Host:       &agent.Host{Root: o.hostRoot, Nsenter: o.nsenter, RuncRoot: v1.RuncRoot},
		NodeName:   nodeName,
		Endpoint:   net.JoinHostPort(ip, strconv.Itoa(o.port)),
		Token:      token,
		Log:        logger.With("node", nodeName),
		TestFaults: o.testFaults,
		PreAttach:  o.preAttach,
		Version:    o.version,

		PhantomSteerMark: o.steerMark,
	}
	if o.caFile != "" {
		a.TransferTLS = &agent.TransferTLS{CAFile: o.caFile, Node: nodeName,
			Request: agent.CertificateRequester(clientset, nodeName)}
	}
	if _, err := os.Stat(o.ciliumSock); err == nil {
		a.Cilium = agent.NewCiliumHooks(o.ciliumSock)
		logger.Info("Cilium agent found – fast IP handover enabled", "socket", o.ciliumSock)
	}
	if o.phantomMode == "auto" {
		pm, err := agent.EnablePhantom(a)
		if err != nil {
			logger.Warn("Phantom mode unavailable on this node", "err", err)
		} else {
			logger.Info("Phantom mode available")
			go func() {
				for range time.Tick(time.Minute) {
					pm.Sweep(context.Background())
				}
			}()
		}
	}
	return a, nil
}

// drainOnSignal returns the agent's context. The first SIGTERM drains
// (internal/agent/shutdown.go): the migrations on this node finish before
// the context ends and the manager stops. A second signal exits.
func drainOnSignal(a *agent.Agent, timeout time.Duration, logger *slog.Logger) context.Context {
	ctx, stop := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		go func() {
			<-sig
			os.Exit(1)
		}()
		logger.Info("shutting down: draining", "timeout", timeout.String())
		a.Drain(context.Background(), timeout)
		stop()
	}()
	return ctx
}

// serveTransfer starts the transfer server – with TLS, once the node's
// certificate is there. The returned channel is closed when it listens.
func serveTransfer(ctx context.Context, a *agent.Agent, token string, logger *slog.Logger) <-chan struct{} {
	srv := &agent.Server{Token: token, Log: logger, Authorize: a.AuthorizeTransfer}
	httpSrv := &http.Server{Addr: a.Endpoint, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 2 * time.Minute,
		// Rejected handshakes (strangers on the node network) land in the
		// agent's log, not on stderr.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn)}
	up := make(chan struct{})
	if a.TransferTLS != nil {
		go a.TransferTLS.Run(ctx, logger)
	}
	go func() {
		if a.TransferTLS != nil {
			if err := a.TransferTLS.Wait(ctx, logger); err != nil {
				return
			}
		}
		ln, err := net.Listen("tcp", a.Endpoint)
		if err != nil {
			logger.Error("transfer server", "err", err)
			os.Exit(1)
		}
		if a.TransferTLS != nil {
			ln = tls.NewListener(ln, a.TransferTLS.ServerConfig())
		}
		logger.Info("transfer server listening", "addr", a.Endpoint, "tls", a.TransferTLS != nil)
		a.MarkTransferUp()
		close(up)
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			logger.Error("transfer server", "err", err)
			os.Exit(1)
		}
	}()
	return up
}

// startBackground starts the commit gate and the agent's janitors and
// keepers.
func startBackground(ctx context.Context, a *agent.Agent, o options, clientset kubernetes.Interface, logger *slog.Logger) {
	if o.commitGate {
		if err := a.StartCommitGate(ctx, clientset, cmp.Or(o.kubeletDir, "/var/lib/kubelet")); err != nil {
			logger.Warn("commit gate unavailable – replacements are released after the final dump", "err", err)
		}
	}
	go a.RunShieldJanitor(ctx)
	go a.RunStateJanitor(ctx)
	if a.Cilium != nil {
		go a.RunRouteKeeper(ctx)
	}
	if a.Phantom != nil {
		go a.Phantom.WatchRoutes(ctx)
	}
	// A scheduled termination (EC2 spot) as paguro.dev/terminates-at.
	if src, err := a.NodeInterruptionSource(ctx); err != nil {
		logger.Warn("node not readable – no watch for interruption notices", "err", err)
	} else if src != nil {
		go a.RunInterruptionWatch(ctx, src)
	}
}

// announce keeps the node's annotations (endpoint, capabilities, release)
// current: right after the transfer server listens, then every five
// minutes – every ten seconds while the endpoint is not published yet. Once
// it is, the node's startup taint goes.
func announce(ctx context.Context, a *agent.Agent, transferUp <-chan struct{}, logger *slog.Logger) {
	tainted := true
	for {
		if err := a.AnnotateNode(context.Background()); err != nil {
			logger.Warn("node annotations", "err", err)
		}
		if tainted && a.Advertised() {
			if err := a.ClearStartupTaint(ctx); err != nil {
				logger.Warn("startup taint", "err", err)
			} else {
				tainted = false
			}
		}
		every := 5 * time.Minute
		if transferUp == nil && (!a.Advertised() || tainted) {
			every = 10 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-transferUp:
			transferUp = nil
		case <-time.After(every):
		}
	}
}

func internalIP(c client.Client, node string) (string, error) {
	n := &corev1.Node{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: node}, n); err != nil {
		return "", err
	}
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address, nil
		}
	}
	return "", fmt.Errorf("node %s has no InternalIP", node)
}
