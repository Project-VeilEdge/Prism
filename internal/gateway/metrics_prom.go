// Package gateway — Prometheus instrumentation for the gateway.
//
// All metrics defined in the blueprint §18: prism_gateway_connections_total,
// prism_gateway_bytes_total, prism_gateway_ech_decrypt_total,
// prism_dns_queries_total, prism_egress_rejected_total, prism_config_version,
// prism_pool_gets_total, prism_pool_misses_total, prism_db_write_queue_length,
// prism_db_write_duration_seconds.
package gateway

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// --- Gateway connection metrics ---

var (
	// GatewayConnectionsTotal counts completed gateway connections.
	GatewayConnectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prism_gateway_connections_total",
		Help: "Total number of gateway connections handled.",
	}, []string{"egress", "status"})

	// GatewayBytesTotal counts bytes relayed through the gateway.
	GatewayBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prism_gateway_bytes_total",
		Help: "Total bytes relayed through the gateway.",
	}, []string{"direction", "egress"})

	// GatewayECHDecryptTotal counts ECH decryption attempts.
	GatewayECHDecryptTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prism_gateway_ech_decrypt_total",
		Help: "Total ECH decryption attempts.",
	}, []string{"result"})

	// GatewayActiveConnections tracks currently active relay connections.
	GatewayActiveConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "prism_gateway_active_connections",
		Help: "Number of currently active relay connections.",
	})
)

// --- DNS metrics ---

var (
	// DNSQueriesTotal counts DNS queries processed.
	DNSQueriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prism_dns_queries_total",
		Help: "Total DNS queries processed.",
	}, []string{"type", "whitelisted"})
)

// --- Egress metrics ---

var (
	// EgressRejectedTotal counts egress node rejections by defense layer.
	EgressRejectedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prism_egress_rejected_total",
		Help: "Total egress node rejections.",
	}, []string{"layer"})
)

// --- Config version ---

var (
	// ConfigVersion tracks the current config version by component.
	ConfigVersion = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "prism_config_version",
		Help: "Current config version.",
	}, []string{"component"})
)

// --- Buffer pool metrics ---

var (
	// PoolGetsTotal counts pool.Get() calls.
	PoolGetsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prism_pool_gets_total",
		Help: "Total sync.Pool Get() calls.",
	}, []string{"pool"})

	// PoolMissesTotal counts pool Get() misses (new allocations).
	PoolMissesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prism_pool_misses_total",
		Help: "Total sync.Pool misses (new allocations).",
	}, []string{"pool"})
)

// --- Database write metrics ---

var (
	// DBWriteQueueLength is the current length of the write serializer channel.
	DBWriteQueueLength = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "prism_db_write_queue_length",
		Help: "Current number of pending write operations in the serializer queue.",
	})

	// DBWriteDurationSeconds observes write transaction durations.
	DBWriteDurationSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "prism_db_write_duration_seconds",
		Help:    "Duration of database write transactions.",
		Buckets: prometheus.ExponentialBuckets(0.001, 2, 12), // 1ms → ~4s
	})
)

// --- PrometheusCollector implements MetricsCollector and feeds Prometheus counters ---

// PrometheusCollector implements MetricsCollector by updating Prometheus counters
// for every recorded connection. It also delegates to an optional inner collector
// (e.g., Reporter) so both Prometheus and gRPC reporting can coexist.
type PrometheusCollector struct {
	Inner MetricsCollector
}

// RecordConn updates Prometheus counters and then delegates to the inner collector.
func (pc *PrometheusCollector) RecordConn(m *ConnMetrics) {
	egress := m.Egress
	if egress == "" {
		egress = m.TrafficType
	}
	if egress == "" {
		egress = "unknown"
	}
	statusLabel := string(m.Status)
	if statusLabel == "" {
		statusLabel = "unknown"
	}

	GatewayConnectionsTotal.WithLabelValues(egress, statusLabel).Inc()

	if m.UpBytes > 0 {
		GatewayBytesTotal.WithLabelValues("up", egress).Add(float64(m.UpBytes))
	}
	if m.DownBytes > 0 {
		GatewayBytesTotal.WithLabelValues("down", egress).Add(float64(m.DownBytes))
	}

	// ECH decrypt result tracking.
	if m.ECHSuccess {
		GatewayECHDecryptTotal.WithLabelValues("success").Inc()
	} else if m.Status == ConnStatusECHDecryptFail {
		GatewayECHDecryptTotal.WithLabelValues("failure").Inc()
	}

	if pc.Inner != nil {
		pc.Inner.RecordConn(m)
	}
}
