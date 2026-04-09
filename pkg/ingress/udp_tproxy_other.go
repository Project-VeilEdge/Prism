//go:build !linux

// Package ingress provides network listener primitives for Prism's inbound traffic.
package ingress

import (
	"fmt"
	"net"
)

// ListenUDPTProxy on non-Linux platforms falls back to a standard UDP listener.
// The IP_TRANSPARENT socket option is Linux-specific; on other platforms we can
// only bind to local addresses. This is sufficient for development and testing.
func ListenUDPTProxy(network, address string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("ingress/tproxy: resolve %q: %w", address, err)
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		return nil, fmt.Errorf("ingress/tproxy: listen %s: %w", address, err)
	}
	return conn, nil
}

// ParseOrigDstAddr is not supported on non-Linux platforms.
// It always returns an error.
func ParseOrigDstAddr(oob []byte) (*net.UDPAddr, error) {
	return nil, fmt.Errorf("ingress/tproxy: ParseOrigDstAddr not supported on this platform")
}
