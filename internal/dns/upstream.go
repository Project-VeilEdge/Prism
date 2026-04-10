package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// Default negative cache TTL for NXDOMAIN responses.
	NegCacheTTL = 300 * time.Second

	// Maximum cache entries before eviction.
	maxCacheEntries = 10000
)

// cacheEntry holds a cached DNS response with its expiry time.
type cacheEntry struct {
	msg       *dns.Msg
	cachedAt  time.Time
	expiresAt time.Time
}

// Upstream performs DNS queries via DoH to upstream resolvers with
// an in-memory TTL cache and negative caching for NXDOMAIN.
type Upstream struct {
	// Endpoints is the list of upstream DoH URLs, tried in order.
	Endpoints []string

	client *http.Client

	mu    sync.RWMutex
	cache map[string]cacheEntry

	// nowFunc is used for testing time-dependent behavior.
	nowFunc func() time.Time
}

// NewUpstream creates an Upstream with the given DoH endpoints.
func NewUpstream(endpoints []string) *Upstream {
	return &Upstream{
		Endpoints: endpoints,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		cache:   make(map[string]cacheEntry),
		nowFunc: time.Now,
	}
}

// cacheKey returns a unique key for a DNS question.
func cacheKey(name string, qtype uint16) string {
	return fmt.Sprintf("%s/%d", dns.CanonicalName(name), qtype)
}

// Query sends a DNS message to upstream resolvers and returns the response.
// Results are cached based on the minimum TTL in the answer section.
// NXDOMAIN responses are cached for NegCacheTTL (300s).
func (u *Upstream) Query(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		key := cacheKey(q.Name, q.Qtype)

		if cached := u.getCache(key); cached != nil {
			resp := cached.Copy()
			resp.Id = msg.Id
			return resp, nil
		}
	}

	resp, err := u.queryUpstream(ctx, msg)
	if err != nil {
		return nil, err
	}

	if len(msg.Question) > 0 && u.isCacheableResponse(resp) {
		q := msg.Question[0]
		key := cacheKey(q.Name, q.Qtype)
		ttl := u.computeTTL(resp)
		u.setCache(key, resp, ttl)
	}

	return resp, nil
}

// getCache retrieves a non-expired cache entry.
func (u *Upstream) getCache(key string) *dns.Msg {
	u.mu.RLock()
	entry, ok := u.cache[key]
	u.mu.RUnlock()

	if !ok || !u.now().Before(entry.expiresAt) {
		return nil
	}
	return u.cloneCachedResponse(entry)
}

// setCache stores a DNS response in the cache with the given TTL.
// When the cache is full, it first sweeps expired entries, then evicts
// random entries if still at capacity — avoiding the thundering-herd
// that a full cache clear would cause.
func (u *Upstream) setCache(key string, msg *dns.Msg, ttl time.Duration) {
	if ttl <= 0 {
		return
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if len(u.cache) >= maxCacheEntries {
		u.evictExpired()
	}
	// If still over 90% capacity after sweeping expired, evict 10% random entries.
	if len(u.cache) >= maxCacheEntries*9/10 {
		u.evictRandom(len(u.cache) / 10)
	}

	u.cache[key] = cacheEntry{
		msg:       msg.Copy(),
		cachedAt:  u.now(),
		expiresAt: u.now().Add(ttl),
	}
}

// evictExpired removes all expired entries. Must be called with u.mu held.
func (u *Upstream) evictExpired() {
	now := u.now()
	for k, v := range u.cache {
		if !now.Before(v.expiresAt) {
			delete(u.cache, k)
		}
	}
}

// evictRandom removes up to n random entries. Must be called with u.mu held.
// Go map iteration order is randomized, so this provides pseudo-random eviction.
func (u *Upstream) evictRandom(n int) {
	i := 0
	for k := range u.cache {
		if i >= n {
			break
		}
		delete(u.cache, k)
		i++
	}
}

// computeTTL returns the cache TTL for a response.
// For NXDOMAIN, returns NegCacheTTL. Otherwise, uses the minimum TTL
// from all answer/authority/additional sections (minimum 10s).
func (u *Upstream) computeTTL(msg *dns.Msg) time.Duration {
	if msg.Rcode == dns.RcodeNameError {
		return NegCacheTTL
	}

	var minTTL uint32 = 0
	first := true

	for _, rr := range append(append(msg.Answer, msg.Ns...), msg.Extra...) {
		hdr := rr.Header()
		if hdr.Rrtype == dns.TypeOPT {
			continue // skip EDNS0 OPT pseudo-record
		}
		if first || hdr.Ttl < minTTL {
			minTTL = hdr.Ttl
			first = false
		}
	}

	if first {
		// No records at all — cache briefly.
		return 30 * time.Second
	}
	if minTTL < 10 {
		minTTL = 10
	}
	return time.Duration(minTTL) * time.Second
}

func (u *Upstream) isCacheableResponse(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	return msg.Rcode == dns.RcodeSuccess || msg.Rcode == dns.RcodeNameError
}

// queryUpstream performs the actual DoH request against upstream endpoints.
func (u *Upstream) queryUpstream(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("dns/upstream: pack query: %w", err)
	}

	var lastErr error
	for _, endpoint := range u.Endpoints {
		resp, err := u.doHTTPQuery(ctx, endpoint, packed)
		if err != nil {
			lastErr = err
			slog.Warn("upstream_query_failed", "endpoint", endpoint, "err", err)
			continue
		}
		return resp, nil
	}

	return nil, fmt.Errorf("dns/upstream: all endpoints failed: %w", lastErr)
}

// doHTTPQuery sends a single DoH POST request and parses the response.
func (u *Upstream) doHTTPQuery(ctx context.Context, endpoint string, query []byte) (*dns.Msg, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	httpResp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d from %s", httpResp.StatusCode, endpoint)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 65535))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var resp dns.Msg
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}

	return &resp, nil
}

func (u *Upstream) now() time.Time {
	if u.nowFunc != nil {
		return u.nowFunc()
	}
	return time.Now()
}

func (u *Upstream) cloneCachedResponse(entry cacheEntry) *dns.Msg {
	resp := entry.msg.Copy()
	age := u.now().Sub(entry.cachedAt)
	if age < 0 {
		age = 0
	}
	ageSeconds := uint32(age / time.Second)

	for _, rr := range append(append(resp.Answer, resp.Ns...), resp.Extra...) {
		hdr := rr.Header()
		if hdr == nil || hdr.Rrtype == dns.TypeOPT {
			continue
		}
		if hdr.Ttl <= ageSeconds {
			hdr.Ttl = 0
			continue
		}
		hdr.Ttl -= ageSeconds
	}

	return resp
}

// CacheLen returns the number of entries in the cache (for testing).
func (u *Upstream) CacheLen() int {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return len(u.cache)
}
