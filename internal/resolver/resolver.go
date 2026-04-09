// Package resolver provides a DNS resolver for the gateway to look up
// real target IPs after ECH decryption reveals the inner SNI.
package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// ResolveResult holds the resolved IPs and TTL for a domain.
type ResolveResult struct {
	IPs []net.IP
	TTL time.Duration
}

// Resolver queries DNS A and AAAA records for a domain via DoH and performs
// loop detection against the gateway's own IPs.
type Resolver struct {
	// Endpoints is the list of upstream DoH URLs, tried in order.
	Endpoints []string

	// SelfIPs are the gateway's own IPs. If a resolved IP matches any
	// of these, the query returns an error to prevent forwarding loops.
	SelfIPs []net.IP

	client *http.Client
}

// NewResolver creates a resolver with the given DoH endpoints and self IPs.
func NewResolver(endpoints []string, selfIPs []net.IP) *Resolver {
	return &Resolver{
		Endpoints: endpoints,
		SelfIPs:   selfIPs,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// ErrLoopDetected is returned when a resolved IP matches the gateway's own IP.
var ErrLoopDetected = errors.New("resolver: loop detected — resolved IP matches gateway self IP")

// Resolve queries DNS A and AAAA records for a domain concurrently,
// merges the results, and checks for forwarding loops.
func (r *Resolver) Resolve(ctx context.Context, domain string) (*ResolveResult, error) {
	fqdn := dns.Fqdn(domain)

	type queryResult struct {
		resp *dns.Msg
		err  error
	}

	aCh := make(chan queryResult, 1)
	aaaaCh := make(chan queryResult, 1)

	go func() {
		msg := new(dns.Msg)
		msg.SetQuestion(fqdn, dns.TypeA)
		resp, err := r.queryUpstream(ctx, msg)
		aCh <- queryResult{resp, err}
	}()
	go func() {
		msg := new(dns.Msg)
		msg.SetQuestion(fqdn, dns.TypeAAAA)
		resp, err := r.queryUpstream(ctx, msg)
		aaaaCh <- queryResult{resp, err}
	}()

	aResult := <-aCh
	aaaaResult := <-aaaaCh

	// Both failing is an error; one succeeding is fine.
	if aResult.err != nil && aaaaResult.err != nil {
		return nil, fmt.Errorf("resolver: query %q: A: %w; AAAA: %v", domain, aResult.err, aaaaResult.err)
	}

	result := &ResolveResult{}
	var minTTL uint32
	first := true

	for _, qr := range []queryResult{aResult, aaaaResult} {
		if qr.err != nil || qr.resp == nil {
			continue
		}
		if qr.resp.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range qr.resp.Answer {
			switch rec := rr.(type) {
			case *dns.A:
				result.IPs = append(result.IPs, rec.A)
				if first || rec.Hdr.Ttl < minTTL {
					minTTL = rec.Hdr.Ttl
					first = false
				}
			case *dns.AAAA:
				result.IPs = append(result.IPs, rec.AAAA)
				if first || rec.Hdr.Ttl < minTTL {
					minTTL = rec.Hdr.Ttl
					first = false
				}
			}
		}
	}

	if len(result.IPs) == 0 {
		return nil, fmt.Errorf("resolver: no A/AAAA records for %q", domain)
	}

	result.TTL = time.Duration(minTTL) * time.Second

	// Loop detection: check if any resolved IP matches SelfIPs.
	for _, resolved := range result.IPs {
		for _, self := range r.SelfIPs {
			if resolved.Equal(self) {
				return nil, fmt.Errorf("%w: %s resolves to self IP %s", ErrLoopDetected, domain, resolved)
			}
		}
	}

	return result, nil
}

// queryUpstream performs a DoH POST request against configured endpoints.
func (r *Resolver) queryUpstream(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}

	var lastErr error
	for _, endpoint := range r.Endpoints {
		resp, err := r.doHTTPQuery(ctx, endpoint, packed)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("all endpoints failed: %w", lastErr)
}

// doHTTPQuery sends a single DoH POST request.
func (r *Resolver) doHTTPQuery(ctx context.Context, endpoint string, query []byte) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	httpResp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d from %s", httpResp.StatusCode, endpoint)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 65535))
	if err != nil {
		return nil, err
	}

	var resp dns.Msg
	if err := resp.Unpack(body); err != nil {
		return nil, err
	}
	return &resp, nil
}
