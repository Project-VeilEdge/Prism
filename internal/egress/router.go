package egress

import (
	"net"
	"strings"
	"sync/atomic"
)

// EgressNode represents a remote egress exit point.
type EgressNode struct {
	Name    string // e.g. "tokyo", "us-west", "direct"
	Address string // e.g. "203.0.113.10:9443"; empty means direct connect
}

// IsDirect returns true if this node represents a direct connection (no egress proxy).
func (n *EgressNode) IsDirect() bool {
	return n.Address == ""
}

// RuleType defines the type of routing rule.
type RuleType int

const (
	RuleTypeDomain  RuleType = iota // Domain match (exact or *.suffix)
	RuleTypeCIDR                    // CIDR match
	RuleTypeGeoIP                   // Country code match
	RuleTypeDefault                 // Default fallback
)

// Rule is a single routing rule associating a match condition with an egress node.
type Rule struct {
	Type      RuleType
	Domain    string       // for RuleTypeDomain: "example.com" or "*.example.com"
	CIDRNets  []*net.IPNet // for RuleTypeCIDR: pre-parsed CIDRs
	Countries []string     // for RuleTypeGeoIP: country codes, e.g. ["JP","KR"]
	Node      *EgressNode
}

// GeoIPLookup is the interface for country lookup by IP.
// *GeoIP satisfies this interface.
type GeoIPLookup interface {
	LookupCountry(ip net.IP) string
}

// Router selects the appropriate EgressNode for a given target.
// Rules are evaluated in strict priority order:
// 1. Domain (exact or *. prefix) -> 2. CIDR -> 3. GeoIP -> 4. Default.
type Router struct {
	rules atomic.Pointer[[]Rule]
	geoip GeoIPLookup
}

// NewRouter creates a Router with the given rules and GeoIP lookup.
// The geoip parameter may be nil (GeoIP rules will never match).
func NewRouter(rules []Rule, geoip GeoIPLookup) *Router {
	r := &Router{geoip: geoip}
	r.rules.Store(&rules)
	return r
}

// Route returns the matching EgressNode for the given domain and target IP.
// Returns nil if no rule matches (should not happen if a default rule exists).
func (r *Router) Route(domain string, targetIP net.IP) *EgressNode {
	rulesPtr := r.rules.Load()
	if rulesPtr == nil {
		return nil
	}
	rules := *rulesPtr

	// Phase 1: Domain rules
	for i := range rules {
		if rules[i].Type == RuleTypeDomain && matchDomain(rules[i].Domain, domain) {
			return rules[i].Node
		}
	}

	// Phase 2: CIDR rules
	for i := range rules {
		if rules[i].Type == RuleTypeCIDR && matchCIDR(rules[i].CIDRNets, targetIP) {
			return rules[i].Node
		}
	}

	// Phase 3: GeoIP rules
	if r.geoip != nil && targetIP != nil {
		country := r.geoip.LookupCountry(targetIP)
		for i := range rules {
			if rules[i].Type == RuleTypeGeoIP && matchCountry(rules[i].Countries, country) {
				return rules[i].Node
			}
		}
	}

	// Phase 4: Default
	for i := range rules {
		if rules[i].Type == RuleTypeDefault {
			return rules[i].Node
		}
	}

	return nil
}

// Reload atomically replaces the rule set.
// The slice is copied defensively to prevent external mutation.
func (r *Router) Reload(rules []Rule) {
	cp := make([]Rule, len(rules))
	copy(cp, rules)
	r.rules.Store(&cp)
}

// RouteAll returns all matching egress nodes in priority order
// (Domain → CIDR → GeoIP → Default). The caller can iterate and
// skip unavailable nodes to implement fallback behavior.
func (r *Router) RouteAll(domain string, targetIP net.IP) []*EgressNode {
	rulesPtr := r.rules.Load()
	if rulesPtr == nil {
		return nil
	}
	rules := *rulesPtr

	var matches []*EgressNode

	// Phase 1: Domain rules
	for i := range rules {
		if rules[i].Type == RuleTypeDomain && matchDomain(rules[i].Domain, domain) {
			matches = append(matches, rules[i].Node)
		}
	}

	// Phase 2: CIDR rules
	for i := range rules {
		if rules[i].Type == RuleTypeCIDR && matchCIDR(rules[i].CIDRNets, targetIP) {
			matches = append(matches, rules[i].Node)
		}
	}

	// Phase 3: GeoIP rules
	if r.geoip != nil && targetIP != nil {
		country := r.geoip.LookupCountry(targetIP)
		for i := range rules {
			if rules[i].Type == RuleTypeGeoIP && matchCountry(rules[i].Countries, country) {
				matches = append(matches, rules[i].Node)
			}
		}
	}

	// Phase 4: Default
	for i := range rules {
		if rules[i].Type == RuleTypeDefault {
			matches = append(matches, rules[i].Node)
		}
	}

	return matches
}

// matchDomain checks if domain matches the pattern.
// Pattern "*.example.com" matches "foo.example.com" and "example.com".
// Pattern "example.com" matches only "example.com".
func matchDomain(pattern, domain string) bool {
	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		base := pattern[2:]   // "example.com"
		return domain == base || strings.HasSuffix(domain, suffix)
	}
	return domain == pattern
}

func matchCIDR(nets []*net.IPNet, ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func matchCountry(countries []string, country string) bool {
	if country == "" {
		return false
	}
	for _, c := range countries {
		if strings.EqualFold(c, country) {
			return true
		}
	}
	return false
}

// ParseCIDRs parses a list of CIDR strings into *net.IPNet at load time.
func ParseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		nets = append(nets, n)
	}
	return nets, nil
}
