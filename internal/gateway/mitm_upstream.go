package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

// UpstreamDialer resolves a server name and establishes a TLS connection
// to the origin on port 443. It implements MITMUpstream.
type UpstreamDialer struct {
	Resolver   Resolver
	MinVersion uint16
	Dialer     *net.Dialer
}

func (d *UpstreamDialer) tlsConfigFor(serverName string) *tls.Config {
	min := d.MinVersion
	if min == 0 {
		min = tls.VersionTLS11
	}
	return &tls.Config{
		ServerName: serverName,
		MinVersion: min,
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// DialTLS resolves serverName, dials TCP to the first IP on port 443,
// and performs a TLS handshake.
func (d *UpstreamDialer) DialTLS(ctx context.Context, serverName string) (*tls.Conn, error) {
	ips, err := d.Resolver.Resolve(ctx, serverName)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no upstream IPs for %s", serverName)
	}
	netDialer := d.Dialer
	if netDialer == nil {
		netDialer = &net.Dialer{}
	}
	raw, err := netDialer.DialContext(ctx, "tcp", net.JoinHostPort(ips[0].String(), "443"))
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, d.tlsConfigFor(serverName))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("upstream handshake: %w", err)
	}
	return tlsConn, nil
}
