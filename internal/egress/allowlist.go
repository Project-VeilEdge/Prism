package egress

import (
	"net"
	"sync/atomic"
)

// Allowlist maintains a set of allowed source IPs, swappable via atomic.Pointer
// for hot reload without locking on the read path.
type Allowlist struct {
	cidrs atomic.Pointer[[]net.IPNet]
}

// NewAllowlist creates an Allowlist from a list of IP addresses and CIDR strings.
// Individual IPs are converted to /32 (IPv4) or /128 (IPv6) CIDRs.
func NewAllowlist(ips []string, cidrs []string) (*Allowlist, error) {
	nets, err := parseAllowEntries(ips, cidrs)
	if err != nil {
		return nil, err
	}
	al := &Allowlist{}
	al.cidrs.Store(&nets)
	return al, nil
}

// Contains checks if the given IP is within any allowed CIDR.
func (al *Allowlist) Contains(ip net.IP) bool {
	nets := al.cidrs.Load()
	if nets == nil {
		return false
	}
	// Normalize to 16-byte form for consistent matching
	ip16 := ip.To16()
	ip4 := ip.To4()
	for _, n := range *nets {
		if n.Contains(ip16) || (ip4 != nil && n.Contains(ip4)) {
			return true
		}
	}
	return false
}

// Reload atomically swaps the allowlist entries.
func (al *Allowlist) Reload(ips []string, cidrs []string) error {
	nets, err := parseAllowEntries(ips, cidrs)
	if err != nil {
		return err
	}
	al.cidrs.Store(&nets)
	return nil
}

func parseAllowEntries(ips []string, cidrs []string) ([]net.IPNet, error) {
	var nets []net.IPNet

	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			// Try as CIDR in case it was misplaced
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, &net.ParseError{Type: "IP address", Text: s}
			}
			nets = append(nets, *n)
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			nets = append(nets, net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
		} else {
			nets = append(nets, net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)})
		}
	}

	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		nets = append(nets, *n)
	}

	return nets, nil
}
