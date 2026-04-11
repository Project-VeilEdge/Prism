package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"prism/internal/egress"
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

type TunnelOpener interface {
	OpenTunnel(ctx context.Context, node *egress.EgressNode, targetIP net.IP, targetPort uint16) (net.Conn, error)
}

type RoutedUpstreamDialer struct {
	UpstreamDialer
	Router       *egress.Router
	TunnelOpener TunnelOpener
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

func (d *UpstreamDialer) netDialer() *net.Dialer {
	if d.Dialer != nil {
		return d.Dialer
	}
	return &net.Dialer{}
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
	netDialer := d.netDialer()

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

func (d *RoutedUpstreamDialer) DialTLS(ctx context.Context, serverName string) (*tls.Conn, error) {
	conn, _, err := d.DialTLSWithRoute(ctx, serverName)
	return conn, err
}

func (d *RoutedUpstreamDialer) DialTLSWithRoute(ctx context.Context, serverName string) (*tls.Conn, string, error) {
	ips, err := d.Resolver.Resolve(ctx, serverName)
	if err != nil {
		return nil, "", err
	}
	if len(ips) == 0 {
		return nil, "", fmt.Errorf("no upstream IPs for %s", serverName)
	}

	var errs []error
	for _, ip := range ips {
		for _, node := range d.routeCandidates(serverName, ip) {
			tlsConn, route, err := d.dialCandidate(ctx, serverName, ip, node)
			if err == nil {
				return tlsConn, route, nil
			}
			errs = append(errs, err)
		}
	}

	return nil, "", errors.Join(errs...)
}

func (d *RoutedUpstreamDialer) routeCandidates(serverName string, targetIP net.IP) []*egress.EgressNode {
	if d.Router == nil {
		return []*egress.EgressNode{{Name: "direct"}}
	}
	nodes := d.Router.RouteAll(serverName, targetIP)
	if len(nodes) == 0 {
		return []*egress.EgressNode{{Name: "direct"}}
	}
	return nodes
}

func (d *RoutedUpstreamDialer) dialCandidate(ctx context.Context, serverName string, ip net.IP, node *egress.EgressNode) (*tls.Conn, string, error) {
	raw, route, err := d.openRawConn(ctx, ip, node)
	if err != nil {
		return nil, route, err
	}

	tlsConn := tls.Client(raw, d.tlsConfigFor(serverName))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		slog.Debug("routed upstream handshake failed", "ip", ip, "server", serverName, "route", route, "err", err)
		return nil, route, fmt.Errorf("handshake %s via %s: %w", net.JoinHostPort(ip.String(), d.port()), route, err)
	}
	return tlsConn, route, nil
}

func (d *RoutedUpstreamDialer) openRawConn(ctx context.Context, ip net.IP, node *egress.EgressNode) (net.Conn, string, error) {
	route := "direct"
	if node != nil && !node.IsDirect() && node.Name != "" {
		route = node.Name
	}

	if node == nil || node.IsDirect() {
		addr := net.JoinHostPort(ip.String(), d.port())
		raw, err := d.netDialer().DialContext(ctx, "tcp", addr)
		if err != nil {
			slog.Debug("routed direct dial failed", "ip", ip, "route", route, "err", err)
			return nil, route, fmt.Errorf("dial %s via %s: %w", addr, route, err)
		}
		return raw, route, nil
	}

	if d.TunnelOpener == nil {
		return nil, route, fmt.Errorf("open tunnel via %s: tunnel opener not configured", route)
	}

	port, err := strconv.Atoi(d.port())
	if err != nil {
		return nil, route, fmt.Errorf("parse upstream port %q: %w", d.port(), err)
	}

	raw, err := d.TunnelOpener.OpenTunnel(ctx, node, ip, uint16(port))
	if err != nil {
		slog.Debug("routed tunnel open failed", "ip", ip, "route", route, "err", err)
		return nil, route, fmt.Errorf("open tunnel %s via %s: %w", net.JoinHostPort(ip.String(), d.port()), route, err)
	}
	return raw, route, nil
}
