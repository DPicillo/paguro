// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// kubectl-paguro: kubectl plugin for Paguro live migrations.
//
//	kubectl paguro migrate <pod> [-n ns] [--to node] [--wait] ...
//	kubectl paguro list | describe <migration> | drain <node> | nodes | version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"paguro.dev/paguro/api/v1alpha1"
)

const usage = `kubectl paguro – live migration of running pods (RAM, PVCs, IP, TCP)

Usage:
  kubectl paguro migrate <pod> [-n ns] [--to node] [--strategy PreCopy|StopAndCopy]
                         [--network Auto|Preserve|Phantom|Generic] [--cpu-policy Strict|Ignore]
                         [--freeze-budget 500ms] [--no-auto-converge] [--timeout 10m] [--wait]
  kubectl paguro list [-n ns | -A]
  kubectl paguro describe <migration> [-n ns]
  kubectl paguro drain <node> [--selector k=v] [--parallel N] [--to node] [...migrate flags]
  kubectl paguro nodes
  kubectl paguro version [--client]

Global flags: --kubeconfig, --context, -n/--namespace
`

// globals are the flags every command understands.
type globals struct {
	kubeconfig, kubeContext, namespace string
	allNamespaces                      bool
	// timeout bounds every request (0: the client's defaults; watches and
	// waits need that).
	timeout time.Duration
}

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.kubeconfig, "kubeconfig", "", "path to kubeconfig")
	fs.StringVar(&g.kubeContext, "context", "", "kubeconfig context")
	fs.StringVar(&g.namespace, "namespace", "", "namespace")
	fs.StringVar(&g.namespace, "n", "", "namespace (shorthand)")
	fs.BoolVar(&g.allNamespaces, "all-namespaces", false, "all namespaces")
	fs.BoolVar(&g.allNamespaces, "A", false, "all namespaces (shorthand)")
}

// connect builds the client and determines the effective namespace.
func (g *globals) connect() (client.Client, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if g.kubeconfig != "" {
		rules.ExplicitPath = g.kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: g.kubeContext}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, "", err
	}
	cfg.UserAgent = "kubectl-paguro"
	if g.timeout > 0 {
		cfg.Timeout = g.timeout
	}
	ns := g.namespace
	if ns == "" {
		if ns, _, err = cc.Namespace(); err != nil {
			return nil, "", err
		}
	}
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	return c, ns, err
}

// parseInterspersed allows flags before and after positional arguments
// (kubectl style), which the flag package cannot do on its own.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		if args[0] == "--" {
			return append(positional, args[1:]...), nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

type command func(ctx context.Context, args []string) error

func main() {
	commands := map[string]command{
		"migrate":  cmdMigrate,
		"list":     cmdList,
		"ls":       cmdList,
		"describe": cmdDescribe,
		"drain":    cmdDrain,
		"nodes":    cmdNodes,
		"version":  cmdVersion,
	}
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		fmt.Print(usage)
		return
	}
	cmd, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cmd(ctx, os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		var exit exitError
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		fmt.Fprintln(os.Stderr, paint("error: ", sRed, sBold)+err.Error())
		os.Exit(1)
	}
}

// exitError exits with a code and no further output (the result was already shown).
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func printLines(lines []string) {
	fmt.Println(strings.Join(lines, "\n"))
}
