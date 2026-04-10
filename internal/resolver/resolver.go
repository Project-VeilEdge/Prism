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
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultQueryTimeout = 8 * time.Second
	maxCacheEntries     = 10000
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

	mu    sync.RWMutex
	cache map[string]cacheEntry

	nowFunc func() time.Time
}

type cacheEntry struct {
	result    *ResolveResult
	cachedAt  time.Time
	expiresAt time.Time
}

// NewResolver creates a resolver with the given DoH endpoints and self IPs.
func NewResolver(endpoints []string, selfIPs []net.IP) *Resolver {
	return &Resolver{
		Endpoints: endpoints,
		SelfIPs:   selfIPs,
		client: &http.Client{
			Timeout: defaultQueryTimeout,
		},
		cache:   make(map[string]cacheEntry),
		nowFunc: time.Now,
	}
}

// ErrLoopDetected is returned when a resolved IP matches the gateway's own IP.
var ErrLoopDetected = errors.New("resolver: loop detected — resolved IP matches gateway self IP")

// Resolve queries DNS A and AAAA records for a domain concurrently,
// merges the results, and checks for forwarding loops.
func (r *Resolver) Resolve(ctx context.Context, domain string) (*ResolveResult, error) {
	fqdn := dns.CanonicalName(domain)
	if cached := r.getCache(fqdn); cached != nil {
		return cached, nil
	}

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
			if hdr := rr.Header(); hdr != nil {
				if first || hdr.Ttl < minTTL {
					minTTL = hdr.Ttl
					first = false
				}
			}
			switch rec := rr.(type) {
			case *dns.A:
				result.IPs = append(result.IPs, rec.A)
			case *dns.AAAA:
				result.IPs = append(result.IPs, rec.AAAA)
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

	r.setCache(fqdn, result)
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

func (r *Resolver) getCache(key string) *ResolveResult {
	r.mu.RLock()
	entry, ok := r.cache[key]
	r.mu.RUnlock()

	if !ok || !r.now().Before(entry.expiresAt) {
		return nil
	}

	return cloneResolveResult(entry.result, entry.expiresAt.Sub(r.now()))
}

func (r *Resolver) setCache(key string, result *ResolveResult) {
	if result == nil || result.TTL <= 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.cache) >= maxCacheEntries*9/10 {
		r.evictExpired()
	}
	if len(r.cache) >= maxCacheEntries*9/10 {
		r.evictRandom(len(r.cache) / 10)
	}

	r.cache[key] = cacheEntry{
		result:    cloneResolveResult(result),
		cachedAt:  r.now(),
		expiresAt: r.now().Add(result.TTL),
	}
}

func (r *Resolver) evictExpired() {
	now := r.now()
	for key, entry := range r.cache {
		if !now.Before(entry.expiresAt) {
			delete(r.cache, key)
		}
	}
}

func (r *Resolver) evictRandom(n int) {
	i := 0
	for key := range r.cache {
		if i >= n {
			break
		}
		delete(r.cache, key)
		i++
	}
}

func (r *Resolver) now() time.Time {
	if r.nowFunc != nil {
		return r.nowFunc()
	}
	return time.Now()
}

func cloneResolveResult(result *ResolveResult, ttlOverride ...time.Duration) *ResolveResult {
	if result == nil {
		return nil
	}

	ips := make([]net.IP, len(result.IPs))
	for i, ip := range result.IPs {
		if ip == nil {
			continue
		}
		ips[i] = append(net.IP(nil), ip...)
	}

	ttl := result.TTL
	if len(ttlOverride) > 0 {
		ttl = ttlOverride[0]
		if ttl < 0 {
			ttl = 0
		}
	}

	return &ResolveResult{
		IPs: ips,
		TTL: ttl,
	}
}
