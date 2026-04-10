package dns

import (
	"context"
	"log/slog"
	"net"

	"prism/internal/ech"

	"github.com/miekg/dns"
)

// WhitelistChecker determines whether a domain should be intercepted.
type WhitelistChecker interface {
	Contains(domain string) bool
}

type KeySetProvider interface {
	KeySet() *ech.KeySet
}

// ECHInjector intercepts upstream DNS responses for whitelisted domains.
// For whitelisted queries:
//   - A/AAAA records: replaced with the gateway's own IPs.
//   - HTTPS (Type 65) records: replaced with SVCB containing ECHConfigList.
//
// Non-whitelisted queries are returned unchanged.
type ECHInjector struct {
	Whitelist      WhitelistChecker
	ECHCache       *ECHCache
	GatewayIP      net.IP // Gateway's IPv4 address
	GatewayV6      net.IP // Gateway's IPv6 address (may be nil)
	Upstream       *Upstream
	KeySet         *ech.KeySet // for lazy ECHConfig generation
	KeySource      KeySetProvider
	BaseDomain     string // for lazy ECHConfig generation
	AdvertiseHTTP3 bool
}

// HandleQuery implements the QueryHandler interface. It queries upstream,
// then injects ECH config and gateway IPs for whitelisted domains.
func (inj *ECHInjector) HandleQuery(userHash string, msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		return resp, nil
	}

	qname := msg.Question[0].Name
	domain := stripTrailingDot(qname)
	qtype := msg.Question[0].Qtype

	// For intercepted record types, answer locally so whitelisted traffic does
	// not depend on upstream DoH cache warmth or resolver availability.
	if inj.Whitelist.Contains(domain) {
		switch qtype {
		case dns.TypeA:
			return inj.injectA(msg, qname), nil
		case dns.TypeAAAA:
			return inj.injectAAAA(msg, qname), nil
		case dns.TypeHTTPS:
			return inj.injectHTTPS(msg, qname, userHash), nil
		}
	}

	return inj.passthroughQuery(msg)
}

// injectA replaces the answer with the gateway's A record.
func (inj *ECHInjector) injectA(query *dns.Msg, qname string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(query)

	ip4 := inj.GatewayIP.To4()
	if ip4 == nil {
		return resp
	}

	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: ip4,
		},
	}
	return resp
}

// injectAAAA replaces the answer with the gateway's AAAA record.
func (inj *ECHInjector) injectAAAA(query *dns.Msg, qname string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(query)

	if inj.GatewayV6 == nil {
		return resp
	}

	ip6 := inj.GatewayV6.To16()
	if ip6 == nil {
		return resp
	}

	resp.Answer = []dns.RR{
		&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: ip6,
		},
	}
	return resp
}

// injectHTTPS constructs an HTTPS SVCB record with ECHConfigList from cache.
//
// RFC 9460 HTTPS SVCB record with SvcParamKey ech (0x0005):
//
//	Priority: 1
//	TargetName: "."
//	SvcParams:
//	  - alpn (0x0001): "h2"
//	  - ech (0x0005): ECHConfigList bytes
func (inj *ECHInjector) injectHTTPS(query *dns.Msg, qname string, userHash string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(query)

	echConfigList := inj.ECHCache.Get(userHash)
	keySet := inj.currentKeySet()
	if echConfigList == nil && keySet != nil && inj.BaseDomain != "" {
		// Lazy build: generate ECHConfig for this user on first HTTPS query.
		if err := inj.ECHCache.BuildAndStore(userHash, keySet, inj.BaseDomain); err != nil {
			slog.Warn("dns_ech_cache_build_failed", "user", userHash, "base_domain", inj.BaseDomain, "err", err)
			return resp
		}
		echConfigList = inj.ECHCache.Get(userHash)
	}
	if echConfigList == nil {
		return resp
	}

	svcb := &dns.HTTPS{
		SVCB: dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Priority: 1,
			Target:   ".",
			Value:    buildSVCBParams(echConfigList, inj.AdvertiseHTTP3),
		},
	}

	resp.Answer = []dns.RR{svcb}
	return resp
}

// buildSVCBParams constructs SVCB parameters with alpn and ech.
func buildSVCBParams(echConfigList []byte, advertiseHTTP3 bool) []dns.SVCBKeyValue {
	alpn := []string{"h2"}
	if advertiseHTTP3 {
		alpn = append(alpn, "h3")
	}
	return []dns.SVCBKeyValue{
		&dns.SVCBAlpn{Alpn: alpn},
		&dns.SVCBECHConfig{ECH: echConfigList},
	}
}

// stripTrailingDot removes the trailing dot from a DNS FQDN.
func stripTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func (inj *ECHInjector) currentKeySet() *ech.KeySet {
	if inj == nil {
		return nil
	}
	if inj.KeySource != nil {
		if current := inj.KeySource.KeySet(); current != nil {
			return current
		}
	}
	return inj.KeySet
}

func (inj *ECHInjector) passthroughQuery(msg *dns.Msg) (*dns.Msg, error) {
	resp, err := inj.Upstream.Query(context.Background(), msg)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
