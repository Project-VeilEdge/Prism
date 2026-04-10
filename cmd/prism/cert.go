package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"prism/internal/certs"
	"prism/pkg/mtls"
)

func runCert(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: prism --mode cert <init-ca|issue|acme> [options]")
	}

	switch args[0] {
	case "init-ca":
		return runCertInitCA(args[1:])
	case "issue":
		return runCertIssue(args[1:])
	case "acme":
		return runCertACME(args[1:])
	default:
		return fmt.Errorf("unknown cert sub-command: %s", args[0])
	}
}

func runCertInitCA(args []string) error {
	dir := "configs"
	for i := 0; i < len(args)-1; i += 2 {
		switch args[i] {
		case "--dir":
			dir = args[i+1]
		}
	}

	ca, err := mtls.InitCA()
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	if err := ca.SaveCA(dir); err != nil {
		return err
	}

	slog.Info("ca_init_ok",
		"cert", dir+"/ca-cert.pem",
		"key", dir+"/ca-key.pem",
	)
	return nil
}

func runCertIssue(args []string) error {
	var name, dir, caCert, caKey string
	dir = "configs"
	caCert = "configs/ca-cert.pem"
	caKey = "configs/ca-key.pem"

	for i := 0; i < len(args)-1; i += 2 {
		switch args[i] {
		case "--name":
			name = args[i+1]
		case "--dir":
			dir = args[i+1]
		case "--ca-cert":
			caCert = args[i+1]
		case "--ca-key":
			caKey = args[i+1]
		}
	}

	if name == "" {
		return fmt.Errorf("--name is required (e.g. --name gw-1)")
	}

	ca, err := mtls.LoadCA(caCert, caKey)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	nc, err := ca.IssueCert(name)
	if err != nil {
		return fmt.Errorf("issue cert: %w", err)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	if err := nc.SaveCert(dir, name); err != nil {
		return err
	}

	slog.Info("cert_issue_ok",
		"name", name,
		"cert", dir+"/"+name+"-cert.pem",
		"key", dir+"/"+name+"-key.pem",
	)
	return nil
}

func runCertACME(args []string) error {
	var email, domain, provider, dir, directoryURL string
	var renewBeforeStr string
	dir = certs.DefaultACMECertDir

	for i := 0; i < len(args)-1; i += 2 {
		switch args[i] {
		case "--email":
			email = args[i+1]
		case "--domain":
			domain = args[i+1]
		case "--provider":
			provider = args[i+1]
		case "--dir":
			dir = args[i+1]
		case "--directory":
			directoryURL = args[i+1]
		case "--renew-before":
			renewBeforeStr = args[i+1]
		}
	}

	if domain == "" {
		return fmt.Errorf("--domain is required (e.g. --domain \"*.gw.prism.example.com\")")
	}
	if provider == "" {
		return fmt.Errorf("--provider is required (e.g. --provider cloudflare)")
	}
	if email == "" {
		return fmt.Errorf("--email is required (e.g. --email admin@example.com)")
	}

	renewBefore := 30 * 24 * time.Hour
	if renewBeforeStr != "" {
		d, err := time.ParseDuration(renewBeforeStr)
		if err != nil {
			return fmt.Errorf("invalid --renew-before %q: %w", renewBeforeStr, err)
		}
		renewBefore = d
	}

	// Parse comma-separated domains.
	var domains []string
	for _, d := range splitDomains(domain) {
		if d != "" {
			domains = append(domains, d)
		}
	}

	mgr, err := newACMEManager(certs.ACMEConfig{
		Email:        email,
		Domains:      domains,
		Provider:     provider,
		CertDir:      dir,
		RenewBefore:  renewBefore,
		DirectoryURL: directoryURL,
	})
	if err != nil {
		return fmt.Errorf("init ACME: %w", err)
	}

	if err := mgr.Obtain(); err != nil {
		return fmt.Errorf("obtain cert: %w", err)
	}

	slog.Info("acme_cert_obtained",
		"cert", mgr.CertPath(),
		"key", mgr.KeyPath(),
	)
	return nil
}

func splitDomains(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
