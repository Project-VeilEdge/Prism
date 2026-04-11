package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"prism/internal/gateway"
)

const defaultMITMLeafTTL = 24 * time.Hour

type mitmRuntime struct {
	Enabled            bool
	Issuer             *gateway.MITMIssuer
	UpstreamMinVersion uint16
}

func loadMITMRuntime(cfg *PrismConfig) (*mitmRuntime, error) {
	rt := &mitmRuntime{}
	if cfg == nil || !cfg.MITM.Enable {
		return rt, nil
	}

	if errs := validateMITMCAPaths(cfg); len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}

	rt.Enabled = true

	minVersion, err := parseMITMUpstreamMinVersion(cfg.MITM.UpstreamMinVersion)
	if err != nil {
		return nil, err
	}
	rt.UpstreamMinVersion = minVersion

	issuer, err := gateway.NewMITMIssuer(cfg.MITM.CACert, cfg.MITM.CAKey, defaultMITMLeafTTL)
	if err != nil {
		return nil, fmt.Errorf("load mitm issuer: %w", err)
	}
	rt.Issuer = issuer

	return rt, nil
}

func validateMITMCAPaths(cfg *PrismConfig) []string {
	if cfg == nil || !cfg.MITM.Enable {
		return nil
	}

	var errs []string
	for _, pair := range []struct{ label, path string }{
		{"mitm.ca_cert", cfg.MITM.CACert},
		{"mitm.ca_key", cfg.MITM.CAKey},
	} {
		if pair.path == "" {
			errs = append(errs, fmt.Sprintf("%s is required when mitm.enable=true", pair.label))
			continue
		}
		if _, err := os.Stat(pair.path); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", pair.label, err))
		}
	}
	return errs
}

func parseMITMUpstreamMinVersion(version string) (uint16, error) {
	switch version {
	case "", "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported mitm.upstream_min_version %q", version)
	}
}
