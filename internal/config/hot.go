package config

import (
	"crypto/tls"
	"sync/atomic"

	"prism/internal/ech"
)

// Whitelist is a domain whitelist supporting exact and suffix matches.
// Prefix "." means "this domain and all subdomains".
type Whitelist struct {
	exact  map[string]struct{}
	suffix []string // e.g. ".googleapis.com"
}

// NewWhitelist builds a Whitelist from domain entries.
func NewWhitelist(domains []string) *Whitelist {
	wl := &Whitelist{exact: make(map[string]struct{}, len(domains))}
	for _, d := range domains {
		if len(d) > 0 && d[0] == '.' {
			wl.suffix = append(wl.suffix, d)
			// Also allow the bare domain (e.g. ".foo.com" matches "foo.com")
			wl.exact[d[1:]] = struct{}{}
		} else {
			wl.exact[d] = struct{}{}
		}
	}
	return wl
}

// Contains returns true if domain is whitelisted (exact or suffix match).
func (wl *Whitelist) Contains(domain string) bool {
	if wl == nil {
		return false
	}
	if _, ok := wl.exact[domain]; ok {
		return true
	}
	for _, s := range wl.suffix {
		if len(domain) > len(s) && domain[len(domain)-len(s):] == s {
			return true
		}
	}
	return false
}

// Domains returns the original domain list suitable for serialization.
// Suffix entries are returned with their leading "." prefix.
func (wl *Whitelist) Domains() []string {
	if wl == nil {
		return nil
	}
	// Collect suffix entries first (they are stored with "." prefix).
	seen := make(map[string]struct{}, len(wl.exact)+len(wl.suffix))
	var domains []string
	for _, s := range wl.suffix {
		domains = append(domains, s)
		seen[s] = struct{}{}
		// The bare domain (without ".") was auto-added to exact; skip it.
		seen[s[1:]] = struct{}{}
	}
	for d := range wl.exact {
		if _, dup := seen[d]; !dup {
			domains = append(domains, d)
		}
	}
	return domains
}

// UserEntry is a user record for the in-memory user registry.
type UserEntry struct {
	UserID    string
	Name      string
	Hash      string // SHA256(user_id+":"+salt)[:12]
	Token     string
	Active    bool
	CreatedAt int64 // unix seconds
}

// UserRegistry is a snapshot of all users, indexed by hash for fast lookup.
type UserRegistry struct {
	byHash   map[string]*UserEntry
	byUserID map[string]*UserEntry
}

// NewUserRegistry builds a registry from a slice of users.
func NewUserRegistry(users []*UserEntry) *UserRegistry {
	r := &UserRegistry{
		byHash:   make(map[string]*UserEntry, len(users)),
		byUserID: make(map[string]*UserEntry, len(users)),
	}
	for _, u := range users {
		r.byHash[u.Hash] = u
		r.byUserID[u.UserID] = u
	}
	return r
}

// GetByHash looks up a user by their hex hash (from outer SNI or DoH path).
func (r *UserRegistry) GetByHash(hash string) (*UserEntry, bool) {
	if r == nil {
		return nil, false
	}
	u, ok := r.byHash[hash]
	return u, ok
}

// GetByUserID looks up a user by user_id.
func (r *UserRegistry) GetByUserID(userID string) (*UserEntry, bool) {
	if r == nil {
		return nil, false
	}
	u, ok := r.byUserID[userID]
	return u, ok
}

// All returns all user entries.
func (r *UserRegistry) All() []*UserEntry {
	if r == nil {
		return nil
	}
	out := make([]*UserEntry, 0, len(r.byUserID))
	for _, u := range r.byUserID {
		out = append(out, u)
	}
	return out
}

// Len returns the number of registered users.
func (r *UserRegistry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.byUserID)
}

// EgressIPConfig holds the list of gateway IPs and CIDRs that egress nodes allow.
type EgressIPConfig struct {
	IPs   []string
	CIDRs []string
}

// HotConfig holds all runtime-mutable configuration using atomic.Pointer
// for lock-free reads. Every field is swapped atomically on config reload.
//
// Trigger priority: gRPC push > SIGHUP > fsnotify > periodic mtime check.
// Safety: load failure keeps old config; empty whitelist is rejected.
type HotConfig struct {
	whitelist atomic.Pointer[Whitelist]
	users     atomic.Pointer[UserRegistry]
	egressIPs atomic.Pointer[EgressIPConfig]
	keySet    atomic.Pointer[ech.KeySet]
	tlsCert   atomic.Pointer[tls.Certificate]
	// configVersion tracks the latest version from the controller.
	configVersion atomic.Uint64
}

// NewHotConfig creates a HotConfig with empty defaults.
func NewHotConfig() *HotConfig {
	hc := &HotConfig{}
	// Initialize with empty defaults so Load() never returns nil.
	hc.whitelist.Store(NewWhitelist(nil))
	hc.users.Store(NewUserRegistry(nil))
	hc.egressIPs.Store(&EgressIPConfig{})
	return hc
}

// Whitelist returns the current domain whitelist (never nil).
func (hc *HotConfig) Whitelist() *Whitelist { return hc.whitelist.Load() }

// SwapWhitelist atomically replaces the whitelist. Returns false if
// the new whitelist is nil (safety guard against empty config).
func (hc *HotConfig) SwapWhitelist(wl *Whitelist) bool {
	if wl == nil {
		return false
	}
	hc.whitelist.Store(wl)
	return true
}

// Users returns the current user registry (never nil).
func (hc *HotConfig) Users() *UserRegistry { return hc.users.Load() }

// SwapUsers atomically replaces the user registry.
func (hc *HotConfig) SwapUsers(ur *UserRegistry) {
	if ur == nil {
		ur = NewUserRegistry(nil)
	}
	hc.users.Store(ur)
}

// EgressIPs returns the current egress IP allowlist config.
func (hc *HotConfig) EgressIPs() *EgressIPConfig { return hc.egressIPs.Load() }

// SwapEgressIPs atomically replaces the egress IP config.
func (hc *HotConfig) SwapEgressIPs(cfg *EgressIPConfig) {
	if cfg == nil {
		cfg = &EgressIPConfig{}
	}
	hc.egressIPs.Store(cfg)
}

// ConfigVersion returns the latest applied config version.
func (hc *HotConfig) ConfigVersion() uint64 { return hc.configVersion.Load() }

// SetConfigVersion sets the config version (called after successful apply).
func (hc *HotConfig) SetConfigVersion(v uint64) { hc.configVersion.Store(v) }

// KeySet returns the current ECH key set (may be nil if not yet loaded).
func (hc *HotConfig) KeySet() *ech.KeySet { return hc.keySet.Load() }

// SwapKeySet atomically replaces the ECH key set.
// Returns false if ks is nil (safety guard).
func (hc *HotConfig) SwapKeySet(ks *ech.KeySet) bool {
	if ks == nil {
		return false
	}
	hc.keySet.Store(ks)
	return true
}

// TLSCertificate returns the current TLS certificate for camouflage/DoH (may be nil).
func (hc *HotConfig) TLSCertificate() *tls.Certificate { return hc.tlsCert.Load() }

// SwapTLSCertificate atomically replaces the TLS certificate.
// Returns false if cert is nil (safety guard).
func (hc *HotConfig) SwapTLSCertificate(cert *tls.Certificate) bool {
	if cert == nil {
		return false
	}
	hc.tlsCert.Store(cert)
	return true
}
