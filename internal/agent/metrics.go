// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// The agent's metrics (served by its manager on --metrics-addr). The chart's
// alert rules and dashboard use them (deploy/helm/paguro/files/).
var (
	routeRepairs = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "paguro_agent_route_repairs_total",
		Help: "Cilium host routes of kept addresses that the route keeper restored (ciliumroutes.go).",
	})
	transferRefused = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "paguro_agent_transfer_refused_total",
		Help: "Transfer requests refused: not from the migration's source node, not for this node, unknown migration.",
	})
	stateCleanups = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "paguro_agent_state_cleanups_total",
		Help: "Leftover checkpoint data the state janitor removed, by kind (images, dump, directory).",
	}, []string{"kind"})
	certExpiry = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "paguro_agent_transfer_cert_expiry_timestamp_seconds",
		Help: "When this agent's transfer certificate expires (Unix time); renewed after two thirds of its lifetime.",
	})
)

func init() {
	metrics.Registry.MustRegister(routeRepairs, transferRefused, stateCleanups, certExpiry)
}
