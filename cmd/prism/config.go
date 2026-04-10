package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"prism/internal/egress"

	"gopkg.in/yaml.v3"
)

var validCertModes = map[string]bool{
	"":       true,
	"manual": true,
	"acme":   true,
}

// PrismConfig represents the top-level prism.yaml.
type PrismConfig struct {
	Mode          string `yaml:"mode"`
	WhitelistPath string `yaml:"whitelist_path"`
	UsersPath     string `yaml:"users_path"`
	RoutingPath   string `yaml:"routing_path"`
	GeoIPDBPath   string `yaml:"geoip_db_path"`

	ECH struct {
		PublicName string `yaml:"public_name"`
		KeyPath    string `yaml:"key_path"`
	} `yaml:"ech"`

	Camouflage struct {
		Theme    string `yaml:"theme"`
		SiteName string `yaml:"site_name"`
		Seed     int64  `yaml:"seed"`
	} `yaml:"camouflage"`

	Certs struct {
		Mode   string `yaml:"mode"`
		Manual struct {
			DOHCert     string `yaml:"doh_cert"`
			DOHKey      string `yaml:"doh_key"`
			GatewayCert string `yaml:"gateway_cert"`
			GatewayKey  string `yaml:"gateway_key"`
		} `yaml:"manual"`
		ACME struct {
			Email        string   `yaml:"email"`
			Domains      []string `yaml:"domains"`
			Provider     string   `yaml:"provider"`
			CertDir      string   `yaml:"cert_dir"`
			RenewBefore  string   `yaml:"renew_before"`
			DirectoryURL string   `yaml:"directory_url"`
		} `yaml:"acme"`
	} `yaml:"certs"`

	Controller struct {
		Listen string `yaml:"listen"`
		Store  struct {
			DSN string `yaml:"dsn"`
		} `yaml:"store"`
		MTLS struct {
			CACert     string `yaml:"ca_cert"`
			ServerCert string `yaml:"server_cert"`
			ServerKey  string `yaml:"server_key"`
		} `yaml:"mtls"`
	} `yaml:"controller"`

	Node struct {
		ID         string `yaml:"id"`
		Controller string `yaml:"controller"`
		CachePath  string `yaml:"cache_path"`
		MTLS       struct {
			CACert     string `yaml:"ca_cert"`
			ClientCert string `yaml:"client_cert"`
			ClientKey  string `yaml:"client_key"`
		} `yaml:"mtls"`
	} `yaml:"node"`

	DNS struct {
		ListenDoH           string `yaml:"listen_doh"`
		UpstreamDoH         string `yaml:"upstream_doh"`
		UpstreamDoHFallback string `yaml:"upstream_doh_fallback"`
		SystemFallback      bool   `yaml:"system_fallback"`
		Auth                struct {
			EnableBearerTokens *bool `yaml:"enable_bearer_tokens"`
		} `yaml:"auth"`
		RateLimit struct {
			Enabled          *bool  `yaml:"enabled"`
			MaxRequests      int    `yaml:"max_requests"`
			Window           string `yaml:"window"`
			CleanupTTL       string `yaml:"cleanup_ttl"`
			CleanupFrequency string `yaml:"cleanup_frequency"`
		} `yaml:"rate_limit"`
	} `yaml:"dns"`

	Gateway struct {
		ListenTCP string `yaml:"listen_tcp"`
		ListenUDP string `yaml:"listen_udp"`
		MaxConns  int    `yaml:"max_conns"`
	} `yaml:"gateway"`

	Egress struct {
		Listen             string   `yaml:"listen"`
		StaticAllowIPs     []string `yaml:"static_allow_ips"`
		StaticAllowCIDRs   []string `yaml:"static_allow_cidrs"`
		DenyPrivateTargets bool     `yaml:"deny_private_targets"`
	} `yaml:"egress"`

	MITM struct {
		Enable             bool   `yaml:"enable"`
		CACert             string `yaml:"ca_cert"`
		CAKey              string `yaml:"ca_key"`
		UpstreamMinVersion string `yaml:"upstream_min_version"`
	} `yaml:"mitm"`

	Client struct {
		DNSListen string `yaml:"dns_listen"`
		TLSListen string `yaml:"tls_listen"`
		Gateway   string `yaml:"gateway"`
	} `yaml:"client"`

	Standalone struct {
		AllowLegacyHexUsers bool `yaml:"allow_legacy_hex_users"`
	} `yaml:"standalone"`

	SelfIP     string `yaml:"self_ip"`
	BaseDomain string `yaml:"base_domain"`
	LogLevel   string `yaml:"log_level"`
}

func decodeYAMLStrict(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	return dec.Decode(out)
}

// LoadConfig reads and parses a prism.yaml config file.
func LoadConfig(path string) (*PrismConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg PrismConfig
	if err := decodeYAMLStrict(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// WhitelistConfig represents the whitelist.yaml for validation.
type WhitelistConfig struct {
	Domains []string `yaml:"domains"`
}

func runConfig(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: prism --mode config validate --config <path>")
	}

	switch args[0] {
	case "validate":
		return runConfigValidate(args[1:])
	default:
		return fmt.Errorf("unknown config subcommand %q (expected: validate)", args[0])
	}
}

func requiresRuntimeNodeMTLS(cfg *PrismConfig) (bool, error) {
	if cfg.Mode == "egress" {
		return true, nil
	}
	if cfg.Node.Controller != "" {
		return true, nil
	}
	if cfg.Mode != "gateway" && cfg.Mode != "standalone" {
		return false, nil
	}
	if cfg.RoutingPath == "" {
		return false, nil
	}

	routingCfg, err := egress.LoadRoutingFile(cfg.RoutingPath)
	if err != nil {
		return false, fmt.Errorf("routing_path: %w", err)
	}
	return egress.HasRemoteNodes(routingCfg), nil
}

func runConfigValidate(args []string) error {
	var configPath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 >= len(args) {
				return fmt.Errorf("--config requires a path argument")
			}
			i++
			configPath = args[i]
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}

	if configPath == "" {
		return fmt.Errorf("--config <path> is required")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var cfg PrismConfig
	if err := decodeYAMLStrict(data, &cfg); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}

	var errs []string

	// Validate certs mode.
	if cfg.Certs.Mode != "" && !validCertModes[cfg.Certs.Mode] {
		errs = append(errs, fmt.Sprintf("unknown certs.mode %q", cfg.Certs.Mode))
	}

	// Validate mode.
	if cfg.Mode != "" && !validModes[cfg.Mode] {
		errs = append(errs, fmt.Sprintf("unknown mode %q", cfg.Mode))
	}

	// Validate whitelist file if specified.
	if cfg.WhitelistPath != "" {
		if wlErrs := validateWhitelist(cfg.WhitelistPath); len(wlErrs) > 0 {
			errs = append(errs, wlErrs...)
		}
	}
	if cfg.MITM.Enable {
		if cfg.WhitelistPath == "" {
			errs = append(errs, "whitelist_path is required when mitm.enable=true")
		}
		if _, err := parseMITMUpstreamMinVersion(cfg.MITM.UpstreamMinVersion); err != nil {
			errs = append(errs, err.Error())
		}
		errs = append(errs, validateMITMCAPaths(&cfg)...)
	}

	// Validate ECH key file if specified.
	if cfg.ECH.KeyPath != "" {
		if _, err := os.Stat(cfg.ECH.KeyPath); err != nil {
			errs = append(errs, fmt.Sprintf("ech.key_path: %v", err))
		}
	}
	if cfg.Node.Controller == "" && cfg.ECH.KeyPath == "" {
		switch cfg.Mode {
		case "standalone", "gateway":
			errs = append(errs, fmt.Sprintf("ech.key_path is required in %s mode when node.controller is empty", cfg.Mode))
		}
	}
	if cfg.Mode == "client" && cfg.ECH.KeyPath == "" {
		errs = append(errs, "ech.key_path is required in client mode")
	}

	if cfg.Certs.ACME.RenewBefore != "" {
		if _, err := time.ParseDuration(cfg.Certs.ACME.RenewBefore); err != nil {
			errs = append(errs, fmt.Sprintf("certs.acme.renew_before: %v", err))
		}
	}

	// Validate TLS certificate files if manual mode.
	if cfg.Certs.Mode == "manual" {
		for _, pair := range []struct{ label, path string }{
			{"certs.manual.doh_cert", cfg.Certs.Manual.DOHCert},
			{"certs.manual.doh_key", cfg.Certs.Manual.DOHKey},
			{"certs.manual.gateway_cert", cfg.Certs.Manual.GatewayCert},
			{"certs.manual.gateway_key", cfg.Certs.Manual.GatewayKey},
		} {
			if pair.path != "" {
				if _, err := os.Stat(pair.path); err != nil {
					errs = append(errs, fmt.Sprintf("%s: %v", pair.label, err))
				}
			}
		}
	}

	if cfg.Certs.Mode == "acme" {
		if cfg.Certs.ACME.Email == "" {
			errs = append(errs, "certs.acme.email is required when certs.mode=acme")
		}
		if len(cfg.Certs.ACME.Domains) == 0 {
			errs = append(errs, "certs.acme.domains must not be empty when certs.mode=acme")
		}
		if cfg.Certs.ACME.Provider == "" {
			errs = append(errs, "certs.acme.provider is required when certs.mode=acme")
		}
	}

	if cfg.Mode == "controller" {
		for _, pair := range []struct{ label, path string }{
			{"controller.mtls.ca_cert", cfg.Controller.MTLS.CACert},
			{"controller.mtls.server_cert", cfg.Controller.MTLS.ServerCert},
			{"controller.mtls.server_key", cfg.Controller.MTLS.ServerKey},
		} {
			if pair.path == "" {
				errs = append(errs, fmt.Sprintf("%s is required in controller mode", pair.label))
				continue
			}
			if _, err := os.Stat(pair.path); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", pair.label, err))
			}
		}
	}

	needNodeMTLS, err := requiresRuntimeNodeMTLS(&cfg)
	if err != nil {
		errs = append(errs, err.Error())
	}

	if cfg.Node.Controller != "" && cfg.Node.ID == "" {
		errs = append(errs, "node.id is required when node.controller is configured")
	}

	if needNodeMTLS {
		for _, pair := range []struct{ label, path string }{
			{"node.mtls.ca_cert", cfg.Node.MTLS.CACert},
			{"node.mtls.client_cert", cfg.Node.MTLS.ClientCert},
			{"node.mtls.client_key", cfg.Node.MTLS.ClientKey},
		} {
			if pair.path == "" {
				errs = append(errs, fmt.Sprintf("%s is required for this runtime path", pair.label))
				continue
			}
			if _, err := os.Stat(pair.path); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", pair.label, err))
			}
		}
	}

	// Validate camouflage theme — only "minimal" is currently implemented.
	validThemes := map[string]bool{"minimal": true, "": true}
	if !validThemes[cfg.Camouflage.Theme] {
		errs = append(errs, fmt.Sprintf("camouflage.theme: unsupported theme %q (only \"minimal\" is supported)", cfg.Camouflage.Theme))
	}

	// Validate log_level.
	validLogLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true, "": true}
	if !validLogLevels[cfg.LogLevel] {
		errs = append(errs, fmt.Sprintf("log_level: unknown level %q", cfg.LogLevel))
	}

	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "Validation FAILED (%d errors):\n", len(errs))
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
		return fmt.Errorf("config validation failed")
	}

	fmt.Println("Config validation OK:", configPath)
	return nil
}

func validateWhitelist(path string) []string {
	var errs []string

	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("whitelist_path: %v", err)}
	}

	var wl WhitelistConfig
	if err := yaml.Unmarshal(data, &wl); err != nil {
		return []string{fmt.Sprintf("whitelist_path: parse: %v", err)}
	}

	if len(wl.Domains) == 0 {
		errs = append(errs, "whitelist_path: domains list is empty")
	}

	for i, d := range wl.Domains {
		if d == "" {
			errs = append(errs, fmt.Sprintf("whitelist_path: domains[%d] is empty", i))
			continue
		}
		// Suffix entries must start with "."
		if strings.Contains(d, " ") {
			errs = append(errs, fmt.Sprintf("whitelist_path: domains[%d] %q contains spaces", i, d))
		}
	}

	return errs
}
