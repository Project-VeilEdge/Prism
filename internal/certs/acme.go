// Package certs provides certificate management including ACME DNS-01
// automation via the lego library and hot-reloadable TLS certificates.
package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	legodns "github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

// acmeUser implements the registration.User interface required by lego.
type acmeUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration,omitempty"`
	key          crypto.PrivateKey
	KeyPEM       []byte `json:"key_pem,omitempty"`
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// ACMEConfig holds the configuration for ACME certificate management.
type ACMEConfig struct {
	Email        string        // ACME account email
	Domains      []string      // Domains to obtain certs for
	Provider     string        // DNS provider name for lego (e.g., "cloudflare", "alidns")
	CertDir      string        // Directory to store certs
	RenewBefore  time.Duration // Renew when cert expires within this duration
	DirectoryURL string        // ACME directory URL (empty = Let's Encrypt production)
}

// ACMEManager handles ACME certificate issuance and renewal.
type ACMEManager struct {
	cfg      ACMEConfig
	client   *lego.Client
	user     *acmeUser
	reloader *CertReloader // optional: hot-reload on renewal

	mu       sync.Mutex
	resource *certificate.Resource
}

const (
	DefaultACMECertDir = "/var/lib/prism/acme"
	leProductionURL    = "https://acme-v02.api.letsencrypt.org/directory"
	accountFile        = "acme-account.json"
	certFile           = "cert.pem"
	keyFile            = "cert-key.pem"
	issuerFile         = "issuer.pem"
	resourceFile       = "acme-resource.json"
)

// NewACMEManager creates and configures an ACMEManager.
// It initialises the lego client with the specified DNS-01 provider.
// DNS provider credentials are read from environment variables by lego internally.
func NewACMEManager(cfg ACMEConfig) (*ACMEManager, error) {
	if len(cfg.Domains) == 0 {
		return nil, errors.New("acme: no domains specified")
	}
	if cfg.Provider == "" {
		return nil, errors.New("acme: no DNS provider specified")
	}
	if cfg.CertDir == "" {
		cfg.CertDir = DefaultACMECertDir
	}
	if cfg.RenewBefore == 0 {
		cfg.RenewBefore = 30 * 24 * time.Hour // 30 days
	}
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = leProductionURL
	}

	if err := os.MkdirAll(cfg.CertDir, 0o700); err != nil {
		return nil, fmt.Errorf("acme: create cert dir: %w", err)
	}

	// Load or create ACME account.
	user, err := loadOrCreateUser(cfg.CertDir, cfg.Email)
	if err != nil {
		return nil, fmt.Errorf("acme: setup account: %w", err)
	}

	// Create lego config.
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = cfg.DirectoryURL
	legoCfg.Certificate.KeyType = certcrypto.EC256

	// Create lego client.
	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("acme: create client: %w", err)
	}

	// Configure DNS-01 challenge provider.
	dnsProvider, err := legodns.NewDNSChallengeProviderByName(cfg.Provider)
	if err != nil {
		return nil, fmt.Errorf("acme: create DNS provider %q: %w", cfg.Provider, err)
	}
	if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
		return nil, fmt.Errorf("acme: set DNS provider: %w", err)
	}

	// Register the account if needed.
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("acme: register account: %w", err)
		}
		user.Registration = reg
		if err := saveUser(cfg.CertDir, user); err != nil {
			slog.Warn("acme_save_account_failed", "err", err)
		}
	}

	mgr := &ACMEManager{
		cfg:    cfg,
		client: client,
		user:   user,
	}

	// Load existing resource if available.
	mgr.resource = mgr.loadResource()

	return mgr, nil
}

// SetReloader sets the CertReloader to be called after successful renewal.
func (m *ACMEManager) SetReloader(cr *CertReloader) {
	m.reloader = cr
}

// Obtain requests a new certificate from the ACME server for the configured domains.
// It saves the certificate, key, and issuer to the cert directory.
func (m *ACMEManager) Obtain() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	slog.Info("acme_obtain_start", "domains", m.cfg.Domains)

	resource, err := m.client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: m.cfg.Domains,
		Bundle:  true,
	})
	if err != nil {
		return fmt.Errorf("acme: obtain certificate: %w", err)
	}

	if err := m.saveCertificate(resource); err != nil {
		return fmt.Errorf("acme: save certificate: %w", err)
	}

	m.resource = resource
	slog.Info("acme_obtain_ok", "domains", m.cfg.Domains,
		"domain", resource.Domain)

	// Hot-reload the new certificate.
	if m.reloader != nil {
		if err := m.reloader.Reload(); err != nil {
			slog.Error("acme_reload_failed", "err", err)
		}
	}

	return nil
}

// Renew checks if the current certificate needs renewal and renews it if so.
// Returns true if a renewal was performed.
func (m *ACMEManager) Renew() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.resource == nil || len(m.resource.Certificate) == 0 {
		return false, errors.New("acme: no existing certificate to renew")
	}

	// Parse the current certificate to check expiry.
	expiry, err := certExpiry(m.resource.Certificate)
	if err != nil {
		return false, fmt.Errorf("acme: parse cert expiry: %w", err)
	}

	remaining := time.Until(expiry)
	if remaining > m.cfg.RenewBefore {
		slog.Debug("acme_no_renewal_needed",
			"expires_in", remaining.Round(time.Hour),
			"renew_before", m.cfg.RenewBefore)
		return false, nil
	}

	slog.Info("acme_renew_start",
		"domains", m.cfg.Domains,
		"expires_in", remaining.Round(time.Hour))

	resource, err := m.client.Certificate.Renew(*m.resource, true, false, "")
	if err != nil {
		return false, fmt.Errorf("acme: renew: %w", err)
	}

	if err := m.saveCertificate(resource); err != nil {
		return false, fmt.Errorf("acme: save renewed cert: %w", err)
	}

	m.resource = resource
	slog.Info("acme_renew_ok", "domains", m.cfg.Domains)

	if m.reloader != nil {
		if err := m.reloader.Reload(); err != nil {
			slog.Error("acme_reload_after_renew_failed", "err", err)
		}
	}

	return true, nil
}

// RunRenewalLoop starts a background goroutine that checks certificate expiry
// once per day and renews if within the renew_before window.
// It blocks until ctx is cancelled.
func (m *ACMEManager) RunRenewalLoop(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Immediate first check.
	if renewed, err := m.Renew(); err != nil {
		slog.Error("acme_renewal_check_failed", "err", err)
	} else if renewed {
		slog.Info("acme_renewed_on_startup")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if renewed, err := m.Renew(); err != nil {
				slog.Error("acme_renewal_check_failed", "err", err)
			} else if renewed {
				slog.Info("acme_auto_renewed")
			}
		}
	}
}

// CertPath returns the path to the current certificate file.
func (m *ACMEManager) CertPath() string {
	return filepath.Join(m.cfg.CertDir, certFile)
}

// KeyPath returns the path to the current certificate key file.
func (m *ACMEManager) KeyPath() string {
	return filepath.Join(m.cfg.CertDir, keyFile)
}

// saveCertificate writes the ACME resource to disk.
func (m *ACMEManager) saveCertificate(res *certificate.Resource) error {
	writes := map[string][]byte{
		certFile:   res.Certificate,
		keyFile:    res.PrivateKey,
		issuerFile: res.IssuerCertificate,
	}

	for name, data := range writes {
		if len(data) == 0 {
			continue
		}
		path := filepath.Join(m.cfg.CertDir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}

	// Save resource metadata for renewal.
	return m.saveResource(res)
}

func (m *ACMEManager) saveResource(res *certificate.Resource) error {
	data, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(m.cfg.CertDir, resourceFile), data, 0o600)
}

func (m *ACMEManager) loadResource() *certificate.Resource {
	data, err := os.ReadFile(filepath.Join(m.cfg.CertDir, resourceFile))
	if err != nil {
		return nil
	}
	var res certificate.Resource
	if json.Unmarshal(data, &res) != nil {
		return nil
	}
	// Also load the PEM cert data so Renew can parse expiry.
	certData, err := os.ReadFile(filepath.Join(m.cfg.CertDir, certFile))
	if err == nil {
		res.Certificate = certData
	}
	keyData, err := os.ReadFile(filepath.Join(m.cfg.CertDir, keyFile))
	if err == nil {
		res.PrivateKey = keyData
	}
	return &res
}

// certExpiry extracts the NotAfter time from PEM-encoded certificate bytes.
func certExpiry(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, errors.New("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// loadOrCreateUser loads an existing ACME user account from disk,
// or creates a new one with a fresh ECDSA P-256 key.
func loadOrCreateUser(dir, email string) (*acmeUser, error) {
	path := filepath.Join(dir, accountFile)
	data, err := os.ReadFile(path)
	if err == nil {
		user := &acmeUser{}
		if err := json.Unmarshal(data, user); err == nil && len(user.KeyPEM) > 0 {
			block, _ := pem.Decode(user.KeyPEM)
			if block != nil {
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err == nil {
					user.key = key
					user.Email = email // Allow email updates.
					return user, nil
				}
			}
		}
	}

	// Generate new account key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	user := &acmeUser{
		Email:  email,
		key:    key,
		KeyPEM: keyPEM,
	}

	return user, nil
}

func saveUser(dir string, user *acmeUser) error {
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, accountFile), data, 0o600)
}
