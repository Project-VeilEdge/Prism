package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"prism/internal/certs"
)

type serverTLSRuntime struct {
	Config *tls.Config
	// ShutdownFns is only populated for runtimes that need explicit teardown.
	// The ACME-backed runtime ties its watcher and renewal goroutines to the
	// context passed to loadServerTLSRuntime, so it intentionally leaves this
	// empty and relies on context cancellation for shutdown.
	ShutdownFns []func(context.Context) error
}

type acmeManager interface {
	CertPath() string
	KeyPath() string
	SetReloader(*certs.CertReloader)
	Obtain() error
	RunRenewalLoop(context.Context)
}

var newACMEManager = func(cfg certs.ACMEConfig) (acmeManager, error) {
	return certs.NewACMEManager(cfg)
}

func loadServerTLSRuntime(ctx context.Context, cfg *PrismConfig, listener string) (*serverTLSRuntime, error) {
	switch cfg.Certs.Mode {
	case "", "manual":
		certFile, keyFile, err := manualCertPair(cfg, listener)
		if err != nil {
			return nil, err
		}
		tlsCfg, err := loadTLSConfig(ctx, certFile, keyFile)
		if err != nil {
			return nil, err
		}
		return &serverTLSRuntime{Config: tlsCfg}, nil
	case "acme":
		acmeCfg, err := acmeRuntimeConfig(cfg)
		if err != nil {
			return nil, err
		}
		mgr, err := newACMEManager(acmeCfg)
		if err != nil {
			return nil, err
		}
		missingMaterial, err := acmeMaterialMissing(mgr)
		if err != nil {
			return nil, err
		}
		if missingMaterial {
			if err := mgr.Obtain(); err != nil {
				return nil, err
			}
		}
		reloader, err := certs.NewCertReloader(mgr.CertPath(), mgr.KeyPath())
		if err != nil {
			return nil, err
		}
		mgr.SetReloader(reloader)
		go reloader.WatchMtime(ctx, 30*time.Second)
		go mgr.RunRenewalLoop(ctx)
		return &serverTLSRuntime{
			Config:      reloader.TLSConfig(),
			ShutdownFns: nil,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported certs.mode %q", cfg.Certs.Mode)
	}
}

func acmeMaterialMissing(mgr acmeManager) (bool, error) {
	for _, path := range []string{mgr.CertPath(), mgr.KeyPath()} {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return true, nil
			}
			return false, err
		}
	}
	return false, nil
}

func manualCertPair(cfg *PrismConfig, listener string) (string, string, error) {
	switch listener {
	case "doh":
		return cfg.Certs.Manual.DOHCert, cfg.Certs.Manual.DOHKey, nil
	case "gateway":
		return cfg.Certs.Manual.GatewayCert, cfg.Certs.Manual.GatewayKey, nil
	default:
		return "", "", fmt.Errorf("unsupported tls listener %q", listener)
	}
}

func acmeRuntimeConfig(cfg *PrismConfig) (certs.ACMEConfig, error) {
	acmeCfg := certs.ACMEConfig{
		Email:        cfg.Certs.ACME.Email,
		Domains:      append([]string(nil), cfg.Certs.ACME.Domains...),
		Provider:     cfg.Certs.ACME.Provider,
		CertDir:      cfg.Certs.ACME.CertDir,
		DirectoryURL: cfg.Certs.ACME.DirectoryURL,
	}
	if acmeCfg.Email == "" {
		return certs.ACMEConfig{}, fmt.Errorf("certs.acme.email is required when certs.mode=acme")
	}
	if len(acmeCfg.Domains) == 0 {
		return certs.ACMEConfig{}, fmt.Errorf("certs.acme.domains must not be empty when certs.mode=acme")
	}
	if acmeCfg.Provider == "" {
		return certs.ACMEConfig{}, fmt.Errorf("certs.acme.provider is required when certs.mode=acme")
	}
	if cfg.Certs.ACME.RenewBefore != "" {
		d, err := time.ParseDuration(cfg.Certs.ACME.RenewBefore)
		if err != nil {
			return certs.ACMEConfig{}, fmt.Errorf("parse certs.acme.renew_before: %w", err)
		}
		if d <= 0 {
			return certs.ACMEConfig{}, fmt.Errorf("certs.acme.renew_before must be a positive duration")
		}
		acmeCfg.RenewBefore = d
	}
	if acmeCfg.CertDir == "" {
		acmeCfg.CertDir = certs.DefaultACMECertDir
	}
	return acmeCfg, nil
}
