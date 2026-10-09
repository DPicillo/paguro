// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package controller

import (
	"cmp"
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"paguro.dev/paguro/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Metrics are the controller's Prometheus metrics. A dedicated type (instead
// of global variables) so tests can use their own registry.
type Metrics struct {
	Total     *prometheus.CounterVec
	Freeze    prometheus.Histogram
	Phase     *prometheus.HistogramVec
	WireBytes prometheus.Histogram
	Unmutated prometheus.Gauge
}

// NewMetrics creates the metrics and registers them with reg (nil = no
// registration).
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "paguro_migrations_total",
			Help: "Completed migrations by result (Succeeded, Failed, RolledBack).",
		}, []string{"result"}),
		Freeze: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "paguro_migration_freeze_seconds",
			Help: "How long the application was frozen: paused on the source until it runs on the target.",
			// Fine-grained below one second – that is where Paguro should live.
			Buckets: []float64{0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1, 1.5, 2, 3, 5, 10, 30, 60},
		}),
		Phase: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "paguro_migration_phase_seconds",
			Help:    "Time spent per phase.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 14), // 50 ms … ~7 min
		}, []string{"phase"}),
		WireBytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "paguro_migration_wire_bytes",
			Help:    "Bytes transferred per migration (all rounds, rootfs, emptyDir).",
			Buckets: prometheus.ExponentialBuckets(1<<20, 4, 10), // 1 MiB … 256 GiB
		}),
		Unmutated: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "paguro_unmutated_pods",
			Help: "Pods labeled migratable that the webhook did not mutate (created while it was unreachable); restart them.",
		}),
	}
	if reg != nil {
		reg.MustRegister(m.Total, m.Freeze, m.Phase, m.WireBytes, m.Unmutated)
	}
	return m
}

// DefaultMetrics registers with the controller-runtime registry
// (served by the manager's metrics server on :8080).
func DefaultMetrics() *Metrics { return NewMetrics(metrics.Registry) }

// ActiveCollector reports the running migrations at scrape time, from the
// manager's cache: how many per phase, and how long the oldest has been
// running (the alert for stuck migrations).
type ActiveCollector struct {
	Reader client.Reader
	Now    func() time.Time
}

var (
	activeDesc = prometheus.NewDesc("paguro_migrations_active",
		"Migrations not yet finished, by phase.", []string{"phase"}, nil)
	oldestDesc = prometheus.NewDesc("paguro_migration_oldest_active_seconds",
		"Age of the oldest migration not yet finished (0 when there is none).", nil, nil)
)

func (c *ActiveCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- activeDesc
	ch <- oldestDesc
}

func (c *ActiveCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list := &v1alpha1.MigrationList{}
	if err := c.Reader.List(ctx, list); err != nil {
		return
	}
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	counts := map[v1alpha1.Phase]int{}
	var oldest time.Duration
	for _, m := range list.Items {
		if m.Status.Phase.Terminal() {
			continue
		}
		counts[cmp.Or(m.Status.Phase, v1alpha1.PhasePending)]++
		oldest = max(oldest, now.Sub(m.CreationTimestamp.Time))
	}
	for _, p := range []v1alpha1.Phase{v1alpha1.PhasePending, v1alpha1.PhasePreflight, v1alpha1.PhasePreCopy,
		v1alpha1.PhaseFrozen, v1alpha1.PhaseCuttingOver, v1alpha1.PhaseRestoring, v1alpha1.PhaseAborting} {
		ch <- prometheus.MustNewConstMetric(activeDesc, prometheus.GaugeValue, float64(counts[p]), string(p))
	}
	ch <- prometheus.MustNewConstMetric(oldestDesc, prometheus.GaugeValue, oldest.Seconds())
}
