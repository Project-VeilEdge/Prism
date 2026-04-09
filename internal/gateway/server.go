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
	"prism/internal/relay"
	"prism/pkg/stream"
)

const (
	firstReadTimeout = 5 * time.Second
	dialTimeout      = 5 * time.Second
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
}

// Serve starts accepting connections. It blocks until the listener is closed
// or ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	if s.Metrics == nil {
		s.Metrics = NoopCollector{}
	}

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

		go s.handleConn(conn)
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
	// NOTE: Do NOT clear deadline here. Keep the firstReadTimeout active
	// through the ECH decrypt phase. Clear only after decrypt succeeds.

	// Extract user hash from outer SNI.
	userHash := extractUserHash(cr.Parsed.OuterSNI, s.BaseDomain)
	m.UserHash = userHash

	if userHash == "" || !s.Users.IsValidUser(userHash) {
		slog.Warn("gateway_user_invalid", "outer_sni", cr.Parsed.OuterSNI, "remote", conn.RemoteAddr())
		m.Status = ConnStatusNotWhitelisted
		m.ErrorType = "user_invalid"
		conn.Close()
		return
	}

	// Resolve user_id from hash for metrics reporting.
	m.UserID = s.Users.LookupUserID(userHash)

	// Decrypt ECH — use outer SNI as public_name since the DoH-served
	// ECHConfig has a per-user public_name matching the outer SNI.
	keySet := s.currentKeySet()
	if keySet == nil {
		slog.Error("ech_keyset_missing", "outer_sni", cr.Parsed.OuterSNI)
		m.Status = ConnStatusECHDecryptFail
		m.ErrorType = "ech_keyset_missing"
		conn.Close()
		return
	}

	innerSNI, innerCHRecord, err := keySet.DecryptWithPublicName(cr.Parsed, cr.Parsed.OuterSNI)
	if err != nil {
		slog.Error("ech_decrypt_failed", "outer_sni", cr.Parsed.OuterSNI, "err", err)
		m.Status = ConnStatusECHDecryptFail
		m.ErrorType = "ech_decrypt"
		conn.Close()
		return
	}

	// ECH decryption succeeded — clear deadline for long-lived relay.
	conn.SetDeadline(time.Time{})

	m.InnerSNI = innerSNI
	m.ECHSuccess = true
	slog.Info("ech_decrypt_ok", "user", userHash, "sni", innerSNI)

	// Check whitelist.
	if !s.Whitelist.Contains(innerSNI) {
		slog.Warn("gateway_sni_not_whitelisted", "sni", innerSNI, "user", userHash)
		m.Status = ConnStatusNotWhitelisted
		m.ErrorType = "not_whitelisted"
		conn.Close()
		return
	}

	// Resolve target IPs.
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	ips, err := s.Resolver.Resolve(ctx, innerSNI)
	if err != nil {
		slog.Error("gateway_resolve_failed", "sni", innerSNI, "err", err)
		m.Status = ConnStatusResolveFailed
		m.ErrorType = "resolve_failed"
		conn.Close()
		return
	}

	// Route: use the routing engine if configured, otherwise go direct.
	if s.Router == nil {
		// No router — legacy direct-connect path.
		m.Egress = "direct"
		s.handleDirect(conn, ips, innerCHRecord, m)
		return
	}

	// Get the first resolved IP for CIDR/GeoIP matching.
	var firstIP net.IP
	if len(ips) > 0 {
		firstIP = ips[0]
	}

	// Get all matching routes in priority order for fallback.
	nodes := s.Router.RouteAll(innerSNI, firstIP)
	if len(nodes) == 0 {
		// No route matched at all — fall back to direct.
		slog.Warn("gateway_no_route", "sni", innerSNI)
		m.Egress = "direct"
		s.handleDirect(conn, ips, innerCHRecord, m)
		return
	}

	// Try each matched node in order. Skip unavailable egress nodes.
	for _, node := range nodes {
		if node.IsDirect() {
			m.Egress = node.Name
			if m.Egress == "" {
				m.Egress = "direct"
			}
			slog.Info("gateway_route_match", "sni", innerSNI, "egress", m.Egress, "type", "direct")
			s.handleDirect(conn, ips, innerCHRecord, m)
			return
		}

		// Egress node — forward via EgressClient.
		if s.EgressClient == nil {
			slog.Warn("gateway_egress_no_client", "node", node.Name, "sni", innerSNI)
			continue // skip to next rule
		}

		slog.Info("gateway_route_match", "sni", innerSNI, "egress", node.Name, "addr", node.Address)
		m.Egress = node.Name

		fwdCtx, fwdCancel := context.WithTimeout(context.Background(), dialTimeout)
		result, err := s.EgressClient.Forward(fwdCtx, node, conn, firstIP, 443, innerCHRecord)
		fwdCancel()

		if err != nil {
			slog.Warn("gateway_egress_unavailable", "node", node.Name, "err", err, "sni", innerSNI)
			// Continue to next rule — egress not available.
			continue
		}

		// Relay completed successfully (Forward blocks until relay ends).
		if result != nil {
			m.UpBytes = result.UpBytes
			m.DownBytes = result.DownBytes
		}
		m.Status = ConnStatusOK
		conn.Close()
		return
	}

	// All egress nodes exhausted — report failure.
	slog.Error("gateway_all_egress_failed", "sni", innerSNI)
	m.Status = ConnStatusDialFailed
	m.ErrorType = "dial_failed"
	conn.Close()
}

// handleDirect dials the target directly (no egress node) and relays traffic.
func (s *Server) handleDirect(conn net.Conn, ips []net.IP, innerCHRecord []byte, m *ConnMetrics) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	upstream, err := s.dialTarget(ctx, ips)
	if err != nil {
		slog.Error("gateway_dial_failed", "sni", m.InnerSNI, "err", err)
		m.Status = ConnStatusDialFailed
		m.ErrorType = "dial_failed"
		conn.Close()
		return
	}

	// Write the reconstructed inner CH record to upstream.
	if _, err := upstream.Write(innerCHRecord); err != nil {
		slog.Error("gateway_write_inner_ch_failed", "sni", m.InnerSNI, "err", err)
		m.Status = ConnStatusRelayError
		m.ErrorType = "relay_error"
		upstream.Close()
		conn.Close()
		return
	}

	// Start bidirectional relay.
	upWriter, downWriter := relay.NewRelayPair(conn, upstream)
	relay.RelayWithMetrics(conn, upstream, upWriter, downWriter)

	m.UpBytes = upWriter.Bytes()
	m.DownBytes = downWriter.Bytes()
	m.Status = ConnStatusOK

	conn.Close()
	upstream.Close()
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

// dialTarget tries to connect to one of the resolved IPs on port 443.
func (s *Server) dialTarget(ctx context.Context, ips []net.IP) (net.Conn, error) {
	d := s.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: dialTimeout}
	}

	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), "443")
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = err
			continue
		}
		return conn, nil
	}
	return nil, fmt.Errorf("all %d IPs failed: %w", len(ips), lastErr)
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
