package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"prism/internal/ech"
	"prism/internal/egress"
	"prism/pkg/connutil"
	"prism/pkg/stream"
)

const (
	firstReadTimeout = 5 * time.Second

	// TLS alert descriptions used when the gateway cannot complete a
	// connection. Sent as unencrypted fatal alerts before the handshake
	// progresses past ClientHello, so the browser gets a well-formed TLS
	// error instead of PR_END_OF_FILE_ERROR / EOF.
	tlsAlertHandshakeFailure byte = 40 // 0x28
	tlsAlertInternalError    byte = 80 // 0x50
)

// UserMatcher looks up a user by the hash extracted from the outer SNI.
type UserMatcher interface {
	IsValidUser(hash string) bool
	// LookupUserID returns the user_id for a given hash, or "" if not found.
	LookupUserID(hash string) string
}

// WhitelistChecker determines whether a domain is in the whitelist.
type WhitelistChecker interface {
	Contains(domain string) bool
}

// Resolver resolves a domain to IP addresses.
type Resolver interface {
	Resolve(ctx context.Context, domain string) ([]net.IP, error)
}

// Dialer establishes outbound TCP connections.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type ECHKeySource interface {
	KeySet() *ech.KeySet
}

// Server is the main gateway TCP server. It accepts raw TCP connections,
// classifies them as ECH/TLS/non-TLS, and handles each branch accordingly.
type Server struct {
	// Listener is the raw TCP listener (typically :443).
	Listener net.Listener

	// KeySet holds the current ECH key pair(s) for decryption.
	KeySet *ech.KeySet

	// KeySource allows the server to resolve the current ECH key set dynamically.
	KeySource ECHKeySource

	// Users validates user hashes extracted from outer SNI.
	Users UserMatcher

	// Whitelist checks whether a decrypted inner SNI is allowed.
	Whitelist WhitelistChecker

	// Resolver resolves inner SNI to target IPs.
	Resolver Resolver

	// Camouflage handles non-ECH TLS connections.
	Camouflage *Camouflage

	// MITM handles browser-facing intercepted whitelist traffic when enabled.
	MITM MITMProxy

	// Metrics collects per-connection metrics.
	Metrics MetricsCollector

	// Dialer is used for outbound connections. If nil, net.Dialer is used.
	Dialer Dialer

	// BaseDomain is the gateway's base domain (e.g., "gw.example.com").
	// Outer SNI is expected to be "<hash>.gw.<basedomain>".
	BaseDomain string

	// ConnTracker tracks active connections for health checks. May be nil.
	ConnTracker *ConnectionTracker

	// Router selects egress routes based on domain/CIDR/GeoIP/default rules.
	// If nil, all traffic goes direct.
	Router *egress.Router

	// EgressClient forwards traffic to remote egress nodes via mTLS.
	// Required when Router is non-nil and routes to non-direct nodes.
	EgressClient *egress.Client

	// MaxConns is the maximum number of concurrent connections.
	// If zero, defaults to 10000.
	MaxConns int
}

// Serve starts accepting connections. It blocks until the listener is closed
// or ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	if s.MITM == nil {
		slog.Warn("gateway_mitm_not_configured",
			"msg", "MITM proxy is required for ECH traffic; whitelisted connections will be rejected")
	}
	if s.Metrics == nil {
		s.Metrics = NoopCollector{}
	}
	maxConns := s.MaxConns
	if maxConns <= 0 {
		maxConns = 10000
	}
	sem := make(chan struct{}, maxConns)

	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("gateway: accept: %w", err)
		}

		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				s.handleConn(conn)
			}()
		default:
			slog.Warn("gateway_conn_limit", "max", maxConns)
			sendTLSAlert(conn, tlsAlertInternalError)
			conn.Close()
		}
	}
}

// HandleConn processes a single accepted connection through classification
// and the appropriate branch. Exported for use by standalone SNI dispatch.
func (s *Server) HandleConn(conn net.Conn) {
	if s.Metrics == nil {
		s.Metrics = NoopCollector{}
	}
	s.handleConn(conn)
}

// handleConn processes a single accepted connection through classification
// and the appropriate branch.
func (s *Server) handleConn(conn net.Conn) {
	if s.ConnTracker != nil {
		s.ConnTracker.Add(1)
	}
	GatewayActiveConnections.Inc()

	startTime := time.Now()
	m := &ConnMetrics{
		StartTime:  startTime,
		RemoteAddr: conn.RemoteAddr().String(),
	}

	defer func() {
		if s.ConnTracker != nil {
			s.ConnTracker.Add(-1)
		}
		GatewayActiveConnections.Dec()
		m.EndTime = time.Now()
		m.Duration = m.EndTime.Sub(startTime)
		s.Metrics.RecordConn(m)
	}()

	// Set first-read timeout to prevent slowloris.
	conn.SetReadDeadline(time.Now().Add(firstReadTimeout))

	rr := stream.NewRecordReader(conn)
	cr, err := Classify(rr)
	if err != nil {
		slog.Debug("gateway_classify_fail", "err", err, "remote", conn.RemoteAddr())
		m.Status = ConnStatusClassifyFail
		m.ErrorType = "classify_fail"
		conn.Close()
		return
	}

	m.TrafficType = cr.Type.String()

	switch cr.Type {
	case TrafficECH:
		s.handleECH(conn, cr, m)
	case TrafficTLS:
		s.handleCamouflage(conn, cr, m)
	case TrafficNonTLS:
		m.Status = ConnStatusNonTLS
		m.ErrorType = "non_tls"
		conn.Close()
	}
}

// handleECH processes a connection with an ECH ClientHello.
func (s *Server) handleECH(conn net.Conn, cr *ClassifyResult, m *ConnMetrics) {
	// Extract user hash from outer SNI.
	outerSNI := cr.Parsed.OuterSNI
	userHash := extractUserHash(outerSNI, s.BaseDomain)
	m.UserHash = userHash

	if userHash == "" || !s.Users.IsValidUser(userHash) {
		slog.Warn("gateway_user_invalid", "outer_sni", outerSNI, "remote", conn.RemoteAddr())
		m.Status = ConnStatusNotWhitelisted
		m.ErrorType = "user_invalid"
		sendTLSAlert(conn, tlsAlertInternalError)
		conn.Close()
		return
	}

	// Resolve user_id from hash for metrics reporting.
	m.UserID = s.Users.LookupUserID(userHash)

	// The browser-facing MITM path owns server-side ECH acceptance and inner-host
	// selection. Once the first record has been classified, clear the deadline so
	// the native browser-side TLS handshake can proceed normally.
	conn.SetDeadline(time.Time{})

	// MITM is the sole connection handler for whitelisted ECH traffic.
	// It terminates TLS on both sides (browser ↔ gateway, gateway ↔ upstream),
	// letting Go's crypto/tls handle protocol negotiation, ECH acceptance, HRR,
	// version fallback, and cipher suite selection automatically.
	if s.MITM == nil {
		slog.Error("gateway_mitm_not_configured", "outer_sni", outerSNI)
		m.Status = ConnStatusRelayError
		m.ErrorType = "mitm_not_configured"
		sendTLSAlert(conn, tlsAlertInternalError)
		conn.Close()
		return
	}
	mitmConn := connutil.NewPrefixConn(conn, cr.Record)
	if err := s.MITM.Handle(context.Background(), mitmConn, outerSNI, m); err != nil {
		slog.Error("gateway_mitm_failed", "outer_sni", outerSNI, "err", err)
		m.Status = ConnStatusRelayError
		if m.ErrorType == "" {
			m.ErrorType = "mitm_failed"
		}
		if alert, ok := tlsAlertForMITMError(m.ErrorType); ok {
			sendTLSAlert(conn, alert)
		}
		conn.Close()
		return
	}
	m.Status = ConnStatusOK
	conn.Close()
}

func tlsAlertForMITMError(errorType string) (byte, bool) {
	switch errorType {
	case "browser_tls":
		return 0, false
	case "dns_resolve", "dial_refused", "dial_timeout", "upstream_tls", "relay":
		return tlsAlertHandshakeFailure, true
	default:
		return tlsAlertInternalError, true
	}
}

// handleCamouflage processes a TLS connection without ECH.
func (s *Server) handleCamouflage(conn net.Conn, cr *ClassifyResult, m *ConnMetrics) {
	// Clear the first-read deadline.
	conn.SetDeadline(time.Time{})

	m.Status = ConnStatusCamouflage

	if s.Camouflage == nil {
		conn.Close()
		return
	}

	s.Camouflage.Serve(conn, cr.Record)
}

func (s *Server) currentKeySet() *ech.KeySet {
	if s == nil {
		return nil
	}
	if s.KeySource != nil {
		if current := s.KeySource.KeySet(); current != nil {
			return current
		}
	}
	return s.KeySet
}

// sendTLSAlert writes a TLS fatal alert record on the wire. Because the
// handshake has not progressed past the browser's ClientHello, the alert is
// sent in the clear (unencrypted). This gives the browser a well-formed TLS
// error (e.g. SSL_ERROR_INTERNAL_ERROR_ALERT) instead of PR_END_OF_FILE_ERROR.
func sendTLSAlert(conn net.Conn, desc byte) {
	alert := [7]byte{
		0x15,       // content_type = alert
		0x03, 0x03, // version = TLS 1.2
		0x00, 0x02, // length = 2
		0x02, // level = fatal
		desc, // description
	}
	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	conn.Write(alert[:])
}

// extractUserHash extracts the 12-char hex hash from the outer SNI.
// Expected format: "<hash>.gw.<basedomain>" or "<hash>.<basedomain>".
//
// Returns empty string if extraction fails.
func extractUserHash(outerSNI, baseDomain string) string {
	if outerSNI == "" || baseDomain == "" {
		return ""
	}

	// Try "<hash>.gw.<basedomain>" first.
	gwSuffix := ".gw." + baseDomain
	if strings.HasSuffix(outerSNI, gwSuffix) {
		hash := strings.TrimSuffix(outerSNI, gwSuffix)
		if isValidHash(hash) {
			return hash
		}
	}

	// Fallback: "<hash>.<basedomain>".
	suffix := "." + baseDomain
	if strings.HasSuffix(outerSNI, suffix) {
		hash := strings.TrimSuffix(outerSNI, suffix)
		if isValidHash(hash) {
			return hash
		}
	}

	return ""
}

// isValidHash checks if s is a 12-character hex string.
func isValidHash(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
