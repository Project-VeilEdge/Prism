package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"prism/internal/relay"
)

const (
	egressDialTimeout = 5 * time.Second
	frameReadTimeout  = 5 * time.Second
)

// Server is the egress server running on an exit node.
// It listens on an mTLS port and implements four layers of defense:
//  1. Source IP allowlist (silent close)
//  2. mTLS verification (handled by tls.Server)
//  3. Frame magic validation
//  4. Anti-SSRF: reject private target IPs
type Server struct {
	Allowlist          *Allowlist
	TLSConfig          *tls.Config
	DenyPrivateTargets bool // when true, reject private/loopback target IPs (anti-SSRF)
	Listener           net.Listener

	mu     sync.Mutex
	cancel context.CancelFunc
}

// ListenAndServe starts the egress server on the given address.
func (s *Server) ListenAndServe(addr string) error {
	// Layer 1 is checked before TLS; we use a raw TCP listener,
	// then wrap accepted connections in TLS ourselves.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("egress server: listen: %w", err)
	}

	s.mu.Lock()
	s.Listener = ln
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.mu.Unlock()

	slog.Info("egress_server_started", "addr", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				slog.Error("egress_accept", "err", err)
				continue
			}
		}
		go s.handleConn(conn)
	}
}

// Close shuts down the egress server.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.Listener != nil {
		return s.Listener.Close()
	}
	return nil
}

func (s *Server) handleConn(rawConn net.Conn) {
	defer rawConn.Close()

	// === Layer 1: Source IP Allowlist ===
	remoteAddr := rawConn.RemoteAddr()
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return
	}
	sourceIP := net.ParseIP(host)
	if sourceIP == nil || !s.Allowlist.Contains(sourceIP) {
		// Silent close: no response, no TLS alert
		slog.Debug("egress_reject_allowlist", "remote", remoteAddr)
		return
	}

	// === Layer 2: mTLS Verification ===
	// tls.Server with RequireAndVerifyClientCert handles this automatically
	tlsConn := tls.Server(rawConn, s.TLSConfig)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("egress_reject_mtls", "remote", remoteAddr, "err", err)
		return // rawConn closed by defer
	}
	tlsConn.SetDeadline(time.Time{}) // clear handshake deadline

	defer tlsConn.Close() // sends TLS close_notify before rawConn closes

	// === Layer 3: Frame Protocol Validation ===
	tlsConn.SetReadDeadline(time.Now().Add(frameReadTimeout))
	frame, err := ReadFrame(tlsConn)
	if err != nil {
		slog.Debug("egress_reject_frame", "remote", remoteAddr, "err", err)
		return
	}
	tlsConn.SetReadDeadline(time.Time{})

	// === Layer 4: Anti-SSRF - Reject Private Target IPs ===
	if s.DenyPrivateTargets && isPrivateIP(frame.TargetIP) {
		slog.Warn("egress_reject_ssrf", "remote", remoteAddr, "target_ip", frame.TargetIP)
		return
	}

	// === All checks passed: Dial real target ===
	targetAddr := net.JoinHostPort(frame.TargetIP.String(), fmt.Sprintf("%d", frame.TargetPort))

	targetConn, err := net.DialTimeout("tcp", targetAddr, egressDialTimeout)
	if err != nil {
		slog.Error("egress_dial_target", "target", targetAddr, "err", err)
		return
	}
	defer targetConn.Close()

	// Read the inner ClientHello and forward it to the target
	tlsConn.SetReadDeadline(time.Now().Add(frameReadTimeout))
	innerCH := make([]byte, frame.InnerCHLen)
	if _, err := io.ReadFull(tlsConn, innerCH); err != nil {
		slog.Error("egress_read_inner_ch", "err", err)
		return
	}
	tlsConn.SetReadDeadline(time.Time{}) // clear for relay phase

	if _, err := targetConn.Write(innerCH); err != nil {
		slog.Error("egress_write_inner_ch", "target", targetAddr, "err", err)
		return
	}

	slog.Debug("egress_relay_start", "target", targetAddr)

	// Bidirectional relay
	upWriter, downWriter := relay.NewRelayPair(tlsConn, targetConn)
	relay.RelayWithMetrics(tlsConn, targetConn, upWriter, downWriter)
}

// privateRanges are pre-parsed CIDR ranges for SSRF checks.
var privateRanges = []*net.IPNet{
	mustParseCIDR("10.0.0.0/8"),     // RFC1918
	mustParseCIDR("172.16.0.0/12"),  // RFC1918
	mustParseCIDR("192.168.0.0/16"), // RFC1918
	mustParseCIDR("fc00::/7"),       // RFC4193 - IPv6 unique local
	mustParseCIDR("100.64.0.0/10"),  // RFC6598 - Carrier-grade NAT
}

// isPrivateIP returns true if ip is a private/reserved address:
// RFC1918 (10/8, 172.16/12, 192.168/16), RFC4193 (fc00::/7), loopback, link-local.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true // treat nil as private (deny)
	}

	// Check for IPv4-mapped IPv6 — extract the IPv4 part
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}

	for _, pr := range privateRanges {
		if pr.Contains(ip) {
			return true
		}
	}

	return false
}

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("egress: invalid CIDR: " + s)
	}
	return n
}
