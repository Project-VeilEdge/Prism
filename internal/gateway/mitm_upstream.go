package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
)

// UpstreamDialer resolves a server name and establishes a TLS connection
// to the origin. It implements MITMUpstream.
type UpstreamDialer struct {
	Resolver   Resolver
	MinVersion uint16
	Dialer     *net.Dialer
	Port       string // upstream port; defaults to "443"

	insecureSkipVerify bool // test-only: skip TLS certificate verification
}

func (d *UpstreamDialer) port() string {
	if d.Port != "" {
		return d.Port
	}
	return "443"
}

func (d *UpstreamDialer) tlsConfigFor(serverName string) *tls.Config {
	min := d.MinVersion
	if min == 0 {
		min = tls.VersionTLS11
	}
	return &tls.Config{
		ServerName:         serverName,
		MinVersion:         min,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: d.insecureSkipVerify,
	}
}

// DialTLS resolves serverName and tries each resolved IP in order,
// dialling TCP and performing a TLS handshake.
// It returns the first successful connection, or a combined error if all IPs fail.
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

	var errs []error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip.String(), d.port())
		raw, err := netDialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			slog.Debug("upstream dial failed", "ip", ip, "server", serverName, "err", err)
			errs = append(errs, fmt.Errorf("dial %s: %w", addr, err))
			continue
		}
		tlsConn := tls.Client(raw, d.tlsConfigFor(serverName))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			raw.Close()
			slog.Debug("upstream handshake failed", "ip", ip, "server", serverName, "err", err)
			errs = append(errs, fmt.Errorf("handshake %s: %w", addr, err))
			continue
		}
		return tlsConn, nil
	}
	return nil, errors.Join(errs...)
}
