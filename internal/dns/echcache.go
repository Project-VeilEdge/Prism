package dns

import (
	"fmt"
	"sync"

	"prism/internal/ech"
)

// ECHCache holds per-user ECHConfigList data for injection into
// HTTPS SVCB DNS responses. Thread-safe for concurrent access.
//
// Each user gets a unique ECHConfig with their user hash as the
// public_name prefix. The cache stores the serialized ECHConfigList
// (one or more ECHConfig entries concatenated with a 2-byte overall
// length prefix per RFC 9849 §4).
type ECHCache struct {
	mu      sync.RWMutex
	configs map[string][]byte // userHash → ECHConfigList wire bytes
}

// NewECHCache creates an empty ECH config cache.
func NewECHCache() *ECHCache {
	return &ECHCache{
		configs: make(map[string][]byte),
	}
}

// BuildAndStore builds an ECHConfigList for the given user hash using
// the provided KeySet and base domain, then stores it in the cache.
//
// The public_name is formatted as: <userHash>.gw.<baseDomain>
//
// ECHConfigList wire format (RFC 9849 §4):
//
//	ECHConfigList {
//	    length: uint16     = total bytes of all ECHConfig entries
//	    ECHConfig entries   (concatenated)
//	}
func (c *ECHCache) BuildAndStore(userHash string, ks *ech.KeySet, baseDomain string) error {
	if ks == nil || ks.Current == nil {
		return fmt.Errorf("echcache: missing current key pair")
	}

	publicName := userHash + ".gw." + baseDomain

	var configs [][]byte

	// Build config for current key.
	kpCopy, err := cloneKeyPairForConfig(ks.Current)
	if err != nil {
		return err
	}
	ech.BuildECHConfig(kpCopy, publicName)
	configs = append(configs, kpCopy.Config)

	// Build config for previous key (dual-key window).
	if ks.Previous != nil {
		prevCopy, err := cloneKeyPairForConfig(ks.Previous)
		if err != nil {
			return err
		}
		ech.BuildECHConfig(prevCopy, publicName)
		configs = append(configs, prevCopy.Config)
	}

	configList := buildECHConfigList(configs)

	c.mu.Lock()
	c.configs[userHash] = configList
	c.mu.Unlock()
	return nil
}

// Get returns the ECHConfigList bytes for a user, or nil if not found.
func (c *ECHCache) Get(userHash string) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.configs[userHash]
}

// Remove deletes the cached entry for a user.
func (c *ECHCache) Remove(userHash string) {
	c.mu.Lock()
	delete(c.configs, userHash)
	c.mu.Unlock()
}

// Clear invalidates all cached ECHConfigList entries.
func (c *ECHCache) Clear() {
	c.mu.Lock()
	c.configs = make(map[string][]byte)
	c.mu.Unlock()
}

// Len returns the number of cached entries (for testing).
func (c *ECHCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.configs)
}

// buildECHConfigList produces the wire-format ECHConfigList from a
// slice of individual ECHConfig byte slices.
//
//	ECHConfigList = uint16(total_length) || ECHConfig[0] || ECHConfig[1] || ...
func buildECHConfigList(configs [][]byte) []byte {
	totalLen := 0
	for _, cfg := range configs {
		totalLen += len(cfg)
	}

	buf := make([]byte, 2+totalLen)
	buf[0] = byte(totalLen >> 8)
	buf[1] = byte(totalLen)

	off := 2
	for _, cfg := range configs {
		copy(buf[off:], cfg)
		off += len(cfg)
	}
	return buf
}

// cloneKeyPairForConfig creates a shallow KeyPair copy with the same
// public key and ConfigID, suitable for BuildECHConfig.
// We use ech.ParsePrivateKeyPEM round-trip since fields are unexported.
func cloneKeyPairForConfig(kp *ech.KeyPair) (*ech.KeyPair, error) {
	if kp == nil {
		return nil, fmt.Errorf("echcache: nil key pair")
	}

	// Re-parse the key from PEM to get an independent copy that
	// BuildECHConfig can write Config into without races.
	clone, err := ech.ParsePrivateKeyPEM(kp.MarshalPrivateKeyPEM())
	if err != nil {
		return nil, fmt.Errorf("echcache: clone key pair: %w", err)
	}
	clone.ConfigID = kp.ConfigID
	return clone, nil
}
