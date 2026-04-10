package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

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
		return errors.New("mitm issuer not configured")
	}
	leaf, err := p.Issuer.CertificateFor(innerSNI)
	if err != nil {
		return fmt.Errorf("issue leaf: %w", err)
	}

	upstream, err := p.Upstream.DialTLS(ctx, innerSNI)
	if err != nil {
		return fmt.Errorf("upstream dial: %w", err)
	}
	defer upstream.Close()

	browserTLS := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err := browserTLS.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("browser handshake: %w", err)
	}
	defer browserTLS.Close()

	upWriter, downWriter := relay.NewRelayPair(browserTLS, upstream)
	relay.RelayWithMetrics(browserTLS, upstream, upWriter, downWriter)
	m.UpBytes = upWriter.Bytes()
	m.DownBytes = downWriter.Bytes()
	return nil
}
