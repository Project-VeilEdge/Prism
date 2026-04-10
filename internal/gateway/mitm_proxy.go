package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"prism/internal/relay"
)

// MITMProxy handles intercepted TLS connections for whitelisted domains.
type MITMProxy interface {
	Handle(ctx context.Context, clientConn net.Conn, innerSNI string, m *ConnMetrics) error
}

// MITMUpstream dials origin servers over TLS.
type MITMUpstream interface {
	DialTLS(ctx context.Context, serverName string) (*tls.Conn, error)
}

// DirectMITMProxy terminates the browser TLS session with a dynamically issued
// leaf certificate and bridges application bytes to/from the real origin.
type DirectMITMProxy struct {
	Issuer   *MITMIssuer
	Upstream MITMUpstream
}

// Handle performs MITM interception:
//  1. Issues a leaf cert for innerSNI
//  2. Dials upstream TLS to the origin
//  3. Completes TLS handshake with the browser using the leaf cert
//  4. Relays application bytes bidirectionally
func (p *DirectMITMProxy) Handle(ctx context.Context, clientConn net.Conn, innerSNI string, m *ConnMetrics) error {
	if p == nil || p.Issuer == nil {
		err := errors.New("mitm issuer not configured")
		m.ErrorType = classifyMITMError(err)
		slog.Debug("mitm_error", "sni", innerSNI, "phase", m.ErrorType, "err", err)
		return err
	}
	leaf, err := p.Issuer.CertificateFor(innerSNI)
	if err != nil {
		err = fmt.Errorf("issue leaf: %w", err)
		m.ErrorType = classifyMITMError(err)
		slog.Debug("mitm_error", "sni", innerSNI, "phase", m.ErrorType, "err", err)
		return err
	}

	upstream, err := p.Upstream.DialTLS(ctx, innerSNI)
	if err != nil {
		err = fmt.Errorf("upstream dial: %w", err)
		m.ErrorType = classifyMITMError(err)
		slog.Debug("mitm_error", "sni", innerSNI, "phase", m.ErrorType, "err", err)
		return err
	}
	defer upstream.Close()

	browserTLS := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := browserTLS.HandshakeContext(ctx); err != nil {
		err = fmt.Errorf("browser handshake: %w", err)
		m.ErrorType = classifyMITMError(err)
		slog.Debug("mitm_error", "sni", innerSNI, "phase", m.ErrorType, "err", err)
		return err
	}
	defer browserTLS.Close()

	upWriter, downWriter := relay.NewRelayPair(browserTLS, upstream)
	relay.RelayWithMetrics(browserTLS, upstream, upWriter, downWriter)
	m.UpBytes = upWriter.Bytes()
	m.DownBytes = downWriter.Bytes()
	if m.UpBytes+m.DownBytes == 0 {
		slog.Debug("mitm_zero_bytes", "sni", innerSNI)
	}
	return nil
}

func classifyMITMError(err error) string {
	if err == nil {
		return "unknown"
	}
	msg := err.Error()

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) || strings.Contains(msg, "no upstream IPs") || strings.Contains(msg, "resolve") {
		return "dns_resolve"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && strings.Contains(msg, "connection refused") {
		return "dial_refused"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "dial_timeout"
	}

	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) || strings.Contains(msg, "upstream handshake") || strings.Contains(msg, "tls:") {
		return "upstream_tls"
	}

	if strings.Contains(msg, "browser handshake") {
		return "browser_tls"
	}

	if strings.Contains(msg, "issue leaf") {
		return "cert_issue"
	}

	if strings.Contains(msg, "relay") || errors.Is(err, io.EOF) {
		return "relay"
	}

	return "unknown"
}
