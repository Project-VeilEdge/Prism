//go:build linux

// Package ingress provides network listener primitives for Prism's inbound traffic.
package ingress

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenUDPTProxy creates a UDP listener with IP_TRANSPARENT set, allowing
// interception of packets destined to arbitrary IPs (transparent proxy mode).
// This requires appropriate iptables TPROXY rules and CAP_NET_ADMIN.
//
// On Linux, it uses raw syscalls to set IP_TRANSPARENT before bind.
// The returned *net.UDPConn can receive packets with their original destination
// address preserved, which can be recovered via ReadMsgUDP (IP_RECVORIGDSTADDR).
func ListenUDPTProxy(network, address string) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("ingress/tproxy: resolve %q: %w", address, err)
	}

	// Determine address family.
	family := syscall.AF_INET6
	if addr.IP.To4() != nil {
		family = syscall.AF_INET
	}

	// Create raw socket so we can set options before bind.
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("ingress/tproxy: socket: %w", err)
	}

	// Set IP_TRANSPARENT — allows binding to non-local addresses and
	// receiving packets not addressed to this host.
	if family == syscall.AF_INET {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("ingress/tproxy: IP_TRANSPARENT: %w", err)
		}
		// IP_RECVORIGDSTADDR lets us retrieve the original destination via ancillary data.
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("ingress/tproxy: IP_RECVORIGDSTADDR: %w", err)
		}
	} else {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("ingress/tproxy: IPV6_TRANSPARENT: %w", err)
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVORIGDSTADDR, 1); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("ingress/tproxy: IPV6_RECVORIGDSTADDR: %w", err)
		}
	}

	// Allow address reuse.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ingress/tproxy: SO_REUSEADDR: %w", err)
	}

	// Bind.
	var sa unix.Sockaddr
	if family == syscall.AF_INET {
		sa4 := &unix.SockaddrInet4{Port: addr.Port}
		if addr.IP != nil {
			copy(sa4.Addr[:], addr.IP.To4())
		}
		sa = sa4
	} else {
		sa6 := &unix.SockaddrInet6{Port: addr.Port}
		if addr.IP != nil {
			copy(sa6.Addr[:], addr.IP.To16())
		}
		sa = sa6
	}

	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ingress/tproxy: bind %s: %w", address, err)
	}

	// Convert raw fd to *net.UDPConn via os.File.
	f := os.NewFile(uintptr(fd), "udp-tproxy")
	if f == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ingress/tproxy: NewFile returned nil")
	}

	fc, err := net.FilePacketConn(f)
	f.Close() // FilePacketConn dups the fd, safe to close the original.
	if err != nil {
		return nil, fmt.Errorf("ingress/tproxy: FilePacketConn: %w", err)
	}

	conn, ok := fc.(*net.UDPConn)
	if !ok {
		fc.Close()
		return nil, fmt.Errorf("ingress/tproxy: unexpected conn type %T", fc)
	}

	return conn, nil
}

// ParseOrigDstAddr extracts the original destination address from the
// out-of-band data returned by ReadMsgUDP when IP_RECVORIGDSTADDR is set.
func ParseOrigDstAddr(oob []byte) (*net.UDPAddr, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("ingress/tproxy: parse control messages: %w", err)
	}

	for _, msg := range msgs {
		// IPv4: SOL_IP / IP_RECVORIGDSTADDR
		if msg.Header.Level == unix.IPPROTO_IP && msg.Header.Type == unix.IP_ORIGDSTADDR {
			if len(msg.Data) < 8 {
				continue
			}
			// struct sockaddr_in: family(2) + port(2) + addr(4)
			port := int(msg.Data[2])<<8 | int(msg.Data[3])
			ip := net.IPv4(msg.Data[4], msg.Data[5], msg.Data[6], msg.Data[7])
			return &net.UDPAddr{IP: ip, Port: port}, nil
		}

		// IPv6: SOL_IPV6 / IPV6_ORIGDSTADDR
		if msg.Header.Level == unix.IPPROTO_IPV6 && msg.Header.Type == unix.IPV6_ORIGDSTADDR {
			if len(msg.Data) < 28 {
				continue
			}
			// struct sockaddr_in6: family(2) + port(2) + flow(4) + addr(16) + scope(4)
			port := int(msg.Data[2])<<8 | int(msg.Data[3])
			ip := make(net.IP, 16)
			copy(ip, msg.Data[8:24])
			return &net.UDPAddr{IP: ip, Port: port}, nil
		}
	}

	return nil, fmt.Errorf("ingress/tproxy: no original destination address in OOB data")
}
