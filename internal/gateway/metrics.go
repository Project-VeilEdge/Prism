package gateway

import (
	"time"
)

// ConnStatus indicates the outcome of a gateway connection.
type ConnStatus string

const (
	ConnStatusOK             ConnStatus = "ok"
	ConnStatusECHDecryptFail ConnStatus = "ech_decrypt_fail"
	ConnStatusNotWhitelisted ConnStatus = "not_whitelisted"
	ConnStatusResolveFailed  ConnStatus = "resolve_failed"
	ConnStatusDialFailed     ConnStatus = "dial_failed"
	ConnStatusRelayError     ConnStatus = "relay_error"
	ConnStatusClassifyFail   ConnStatus = "classify_fail"
	ConnStatusCamouflage     ConnStatus = "camouflage"
	ConnStatusNonTLS         ConnStatus = "non_tls"
)

// ConnMetrics holds per-connection metrics collected when a connection ends.
type ConnMetrics struct {
	// StartTime is when the connection was accepted.
	StartTime time.Time
	// EndTime is when the connection finished.
	EndTime time.Time
	// Duration is the total connection lifetime.
	Duration time.Duration
	// UpBytes is the number of bytes sent client→upstream.
	UpBytes int64
	// DownBytes is the number of bytes sent upstream→client.
	DownBytes int64
	// Status indicates the connection outcome.
	Status ConnStatus
	// ErrorType provides a machine-readable error category (empty on success).
	ErrorType string
	// TrafficType records whether the connection was ECH, TLS, or non-TLS.
	TrafficType string
	// UserHash is the user identity extracted from outer SNI (ECH connections only).
	UserHash string
	// UserID is the resolved user_id from the user registry (ECH connections only).
	UserID string
	// InnerSNI is the decrypted target domain (ECH connections only).
	InnerSNI string
	// RemoteAddr is the client's address.
	RemoteAddr string
	// Egress is the name of the matched egress route (e.g. "direct", "tokyo", "us-west").
	Egress string
	// ECHSuccess indicates whether ECH decryption succeeded.
	ECHSuccess bool
}

// MetricsCollector receives connection metrics when each connection ends.
// Implementations should be safe for concurrent use.
type MetricsCollector interface {
	RecordConn(m *ConnMetrics)
}

// ChannelCollector sends metrics to a channel. Useful for aggregation
// by a background goroutine or for testing.
type ChannelCollector struct {
	C chan *ConnMetrics
}

// NewChannelCollector creates a collector with the given buffer size.
func NewChannelCollector(bufSize int) *ChannelCollector {
	return &ChannelCollector{C: make(chan *ConnMetrics, bufSize)}
}

// RecordConn sends metrics to the channel. Non-blocking: drops if full.
func (cc *ChannelCollector) RecordConn(m *ConnMetrics) {
	select {
	case cc.C <- m:
	default:
	}
}

// NoopCollector discards all metrics. Useful as a default.
type NoopCollector struct{}

// RecordConn is a no-op.
func (NoopCollector) RecordConn(*ConnMetrics) {}
