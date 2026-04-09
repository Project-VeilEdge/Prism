package dns

import (
	"sync"
	"time"
)

// RateLimiter implements per-IP rate limiting for DoH endpoints.
// It uses a sliding window counter: each IP is allowed maxRequests
// within a window period. Expired entries are cleaned up periodically
// via a background goroutine to prevent memory leaks.
type RateLimiter struct {
	maxRequests int
	window      time.Duration
	cleanupTTL  time.Duration

	mu      sync.Mutex
	entries map[string]*rateLimitEntry

	stopCh chan struct{}
	wg     sync.WaitGroup
	nowFn  func() time.Time // for testing
}

type rateLimitEntry struct {
	timestamps []time.Time
	lastAccess time.Time
}

// RateLimiterConfig holds configuration for the rate limiter.
type RateLimiterConfig struct {
	MaxRequests int           // max requests per window (default 5)
	Window      time.Duration // sliding window size (default 1s)
	CleanupTTL  time.Duration // how long to keep idle entries (default 60s)
	CleanupFreq time.Duration // how often to run cleanup (default 30s)
}

// NewRateLimiter creates a new rate limiter. Call Start() to begin
// the cleanup goroutine.
func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 5
	}
	if cfg.Window <= 0 {
		cfg.Window = 1 * time.Second
	}
	if cfg.CleanupTTL <= 0 {
		cfg.CleanupTTL = 60 * time.Second
	}
	if cfg.CleanupFreq <= 0 {
		cfg.CleanupFreq = 30 * time.Second
	}
	rl := &RateLimiter{
		maxRequests: cfg.MaxRequests,
		window:      cfg.Window,
		cleanupTTL:  cfg.CleanupTTL,
		entries:     make(map[string]*rateLimitEntry),
		stopCh:      make(chan struct{}),
		nowFn:       time.Now,
	}
	return rl
}

// Start begins the periodic cleanup goroutine.
func (rl *RateLimiter) Start(cleanupFreq time.Duration) {
	if cleanupFreq <= 0 {
		cleanupFreq = 30 * time.Second
	}
	rl.wg.Add(1)
	go rl.cleanupLoop(cleanupFreq)
}

// Stop stops the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
	rl.wg.Wait()
}

// Allow checks if a request from the given IP should be allowed.
// Returns true if within rate limit, false if exceeded.
func (rl *RateLimiter) Allow(ip string) bool {
	now := rl.nowFn()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.entries[ip]
	if !ok {
		entry = &rateLimitEntry{}
		rl.entries[ip] = entry
	}
	entry.lastAccess = now

	// Prune timestamps older than the window.
	valid := entry.timestamps[:0]
	for _, ts := range entry.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	entry.timestamps = valid

	if len(entry.timestamps) >= rl.maxRequests {
		return false
	}

	entry.timestamps = append(entry.timestamps, now)
	return true
}

func (rl *RateLimiter) cleanupLoop(freq time.Duration) {
	defer rl.wg.Done()
	ticker := time.NewTicker(freq)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopCh:
			return
		}
	}
}

func (rl *RateLimiter) cleanup() {
	now := rl.nowFn()
	cutoff := now.Add(-rl.cleanupTTL)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	for ip, entry := range rl.entries {
		if entry.lastAccess.Before(cutoff) {
			delete(rl.entries, ip)
		}
	}
}

// Len returns the current number of tracked IPs.
func (rl *RateLimiter) Len() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.entries)
}
