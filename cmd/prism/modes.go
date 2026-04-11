package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"prism/internal/certs"
	"prism/internal/client"
	appconfig "prism/internal/config"
	"prism/internal/controller"
	prismdns "prism/internal/dns"
	"prism/internal/ech"
	"prism/internal/egress"
	"prism/internal/gateway"
	"prism/internal/node"
	prismquic "prism/internal/quic"
	"prism/internal/resolver"
	"prism/internal/router"
	"prism/internal/web"
	"prism/pkg/mtls"

	pb "prism/api/proto/control"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v3"
)

// modeResult bundles the output of a mode startup function.
type modeResult struct {
	shutdownFns []func(ctx context.Context) error
	connTracker *gateway.ConnectionTracker
}

func newGatewayMetricsCollector(inner gateway.MetricsCollector) gateway.MetricsCollector {
	return &gateway.PrometheusCollector{Inner: inner}
}

// --- Controller mode ---

func startController(ctx context.Context, cfg *PrismConfig) (*modeResult, error) {
	listen := cfg.Controller.Listen
	if listen == "" {
		listen = ":9090"
	}
	dsn := cfg.Controller.Store.DSN
	if dsn == "" {
		dsn = "prism.db"
	}

	store, err := controller.NewSQLiteStore(dsn)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	if err := seedControllerUsersFromFile(ctx, cfg, store); err != nil {
		store.Close()
		return nil, err
	}

	cs := controller.NewControlServer(store, "prism")
	echState, echUpdate, err := newControllerECHState(cfg, store)
	if err != nil {
		store.Close()
		return nil, err
	}
	if err := seedControllerSnapshots(ctx, cfg, store, cs); err != nil {
		store.Close()
		return nil, err
	}
	if echUpdate != nil {
		cs.BroadcastConfig(echUpdate)
	}

	mtlsCreds, err := loadGRPCMTLSServerCredentials(
		cfg.Controller.MTLS.CACert,
		cfg.Controller.MTLS.ServerCert,
		cfg.Controller.MTLS.ServerKey,
	)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("load controller mTLS: %w", err)
	}

	srv := grpc.NewServer(grpc.Creds(mtlsCreds))
	pb.RegisterConfigSyncServer(srv, cs)
	pb.RegisterNodeReportServer(srv, cs)
	pb.RegisterUserAuditServer(srv, cs)
	pb.RegisterDNSAuditServer(srv, cs)

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("listen %s: %w", listen, err)
	}

	go func() {
		slog.Info("controller_started", "addr", listen)
		if err := srv.Serve(ln); err != nil {
			slog.Error("controller_serve_error", "err", err)
		}
	}()

	shutdownFns := []func(ctx context.Context) error{
		func(_ context.Context) error {
			srv.GracefulStop()
			return nil
		},
		func(_ context.Context) error {
			return store.Close()
		},
	}

	if echState != nil {
		w, err := router.NewWatcher(router.WatcherConfig{
			Files: []string{cfg.ECH.KeyPath},
			OnReload: func(path string) error {
				update, err := echState.ReloadUpdate()
				if err != nil {
					return err
				}
				if update != nil {
					cs.BroadcastConfig(update)
					slog.Info("controller_ech_keys_reloaded", "path", path)
				}
				return nil
			},
		})
		if err != nil {
			slog.Warn("controller_ech_watcher_init_failed", "err", err)
		} else {
			w.Start(ctx)
			shutdownFns = append(shutdownFns, func(_ context.Context) error {
				w.Stop()
				return nil
			})
		}
	}

	return &modeResult{
		shutdownFns: shutdownFns,
	}, nil
}

// --- DNS mode ---

func startDNS(ctx context.Context, cfg *PrismConfig) (*modeResult, error) {
	listen := cfg.DNS.ListenDoH
	if listen == "" {
		listen = ":443"
	}

	hot, err := loadLocalHotConfig(cfg)
	if err != nil {
		return nil, err
	}
	validator := newRuntimeValidator(hot, false)

	var shutdownFns []func(ctx context.Context) error
	var auditor *prismdns.Auditor
	echCache := prismdns.NewECHCache()
	if cfg.Node.Controller != "" {
		if cfg.Node.ID == "" {
			return nil, fmt.Errorf("node.id is required when node.controller is configured")
		}

		nodeCreds, err := loadGRPCMTLSClientCredentials(
			cfg.Node.MTLS.CACert,
			cfg.Node.MTLS.ClientCert,
			cfg.Node.MTLS.ClientKey,
		)
		if err != nil {
			return nil, fmt.Errorf("load node mTLS: %w", err)
		}

		syncClient := node.NewSyncClient(node.SyncClientConfig{
			NodeID:     cfg.Node.ID,
			Target:     cfg.Node.Controller,
			Creds:      nodeCreds,
			Hot:        hot,
			CachePath:  cfg.Node.CachePath,
			PublicName: echPublicName(cfg),
			OnECHKeys: func(*ech.KeySet) error {
				echCache.Clear()
				return nil
			},
		})
		if err := syncClient.LoadCache(); err != nil {
			return nil, fmt.Errorf("load config cache: %w", err)
		}
		syncClient.Start()
		shutdownFns = append(shutdownFns, func(_ context.Context) error {
			syncClient.Stop()
			return nil
		})

		auditor = prismdns.NewAuditor(prismdns.AuditorConfig{
			NodeID: cfg.Node.ID,
			Target: cfg.Node.Controller,
			Creds:  nodeCreds,
		})
		auditor.Start()
		shutdownFns = append(shutdownFns, func(_ context.Context) error {
			auditor.Stop()
			return nil
		})
	}

	// Upstream DoH resolver.
	endpoints := []string{cfg.DNS.UpstreamDoH}
	if cfg.DNS.UpstreamDoHFallback != "" {
		endpoints = append(endpoints, cfg.DNS.UpstreamDoHFallback)
	}
	if len(endpoints) == 0 || endpoints[0] == "" {
		endpoints = []string{"https://1.1.1.1/dns-query"}
	}
	upstream := prismdns.NewUpstream(endpoints)

	// Camouflage web handler.
	theme := cfg.Camouflage.Theme
	if theme == "" {
		theme = "minimal"
	}
	gen := web.NewGenerator(theme, cfg.Camouflage.Seed, cfg.Camouflage.SiteName)
	webHandler := web.NewHandler(gen)

	// Load ECH keys for injection.

	// Build a self-IP for the gateway IP in injected records.
	gwIP := net.ParseIP(cfg.SelfIP)
	if gwIP == nil {
		gwIP = net.ParseIP("127.0.0.1")
	}

	// Whitelist for ECH injection.
	injector := &prismdns.ECHInjector{
		Whitelist:  validator,
		ECHCache:   echCache,
		GatewayIP:  gwIP,
		Upstream:   upstream,
		KeySet:     hot.KeySet(),
		KeySource:  hot,
		BaseDomain: cfg.BaseDomain,
	}

	limiter, cleanupFreq, rateLimitEnabled, err := buildRateLimiter(cfg)
	if err != nil {
		return nil, fmt.Errorf("build dns rate limiter: %w", err)
	}
	tokens := prismdns.TokenValidator(nil)
	if bearerTokensEnabled(cfg) {
		tokens = validator
	}

	dohHandler := &prismdns.DoHHandler{
		Camouflage:   webHandler,
		Users:        validator,
		Tokens:       tokens,
		Limiter:      limiter,
		QueryHandler: injector,
		PathPrefix:   "/dns-query/",
	}
	if auditor != nil {
		dohHandler.Auditor = auditor
	}

	// TLS config for HTTPS.
	dohTLS, err := loadServerTLSRuntime(ctx, cfg, "doh")
	if err != nil {
		if cfg.Certs.Mode == "acme" {
			return nil, fmt.Errorf("load dns tls runtime: %w", err)
		}
		slog.Warn("dns_tls_load_failed", "err", err)
		dohTLS = &serverTLSRuntime{Config: &tls.Config{}}
	}
	shutdownFns = append(shutdownFns, dohTLS.ShutdownFns...)

	httpSrv := &http.Server{
		Handler:      dohHandler,
		TLSConfig:    dohTLS.Config,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("dns listen %s: %w", listen, err)
	}

	tlsLn := tls.NewListener(ln, dohTLS.Config)
	if rateLimitEnabled {
		limiter.Start(cleanupFreq)
		shutdownFns = append(shutdownFns, func(context.Context) error {
			limiter.Stop()
			return nil
		})
	}
	go func() {
		slog.Info("dns_started", "addr", listen)
		if err := httpSrv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
			slog.Error("dns_serve_error", "err", err)
		}
	}()

	return &modeResult{
		shutdownFns: append(shutdownFns, httpSrv.Shutdown),
	}, nil
}

// --- Gateway mode ---

func startGateway(ctx context.Context, cfg *PrismConfig) (*modeResult, error) {
	listen := cfg.Gateway.ListenTCP
	if listen == "" {
		listen = ":443"
	}

	hot, err := loadLocalHotConfig(cfg)
	if err != nil {
		return nil, err
	}
	validator := newRuntimeValidator(hot, false)

	mitmRT, err := loadMITMRuntime(cfg)
	if err != nil {
		return nil, fmt.Errorf("load mitm runtime: %w", err)
	}

	var routingCfg *pb.RoutingConfig
	if cfg.RoutingPath != "" {
		routingCfg, err = egress.LoadRoutingFile(cfg.RoutingPath)
		if err != nil {
			return nil, fmt.Errorf("load routing: %w", err)
		}
	}

	var shutdownFns []func(ctx context.Context) error
	var routingState *routingRuntime
	if routingCfg != nil || cfg.Node.Controller != "" {
		routingState, err = newRoutingRuntime(cfg.GeoIPDBPath, routingCfg)
		if err != nil {
			return nil, fmt.Errorf("init routing runtime: %w", err)
		}
		shutdownFns = append(shutdownFns, func(_ context.Context) error {
			return routingState.Close()
		})
	}

	needEgressClient := cfg.Node.Controller != "" || egress.HasRemoteNodes(routingCfg)
	var egressClient *egress.Client
	if needEgressClient {
		nodeTLS, err := loadMTLSClientTLSConfig(
			cfg.Node.MTLS.CACert,
			cfg.Node.MTLS.ClientCert,
			cfg.Node.MTLS.ClientKey,
		)
		if err != nil {
			return nil, fmt.Errorf("load node mTLS: %w", err)
		}
		egressClient = &egress.Client{TLSConfig: nodeTLS}
	}

	// Resolver.
	upstreamEndpoints := []string{cfg.DNS.UpstreamDoH}
	if cfg.DNS.UpstreamDoHFallback != "" {
		upstreamEndpoints = append(upstreamEndpoints, cfg.DNS.UpstreamDoHFallback)
	}
	if len(upstreamEndpoints) == 0 || upstreamEndpoints[0] == "" {
		upstreamEndpoints = []string{"https://1.1.1.1/dns-query"}
	}
	selfIP := net.ParseIP(cfg.SelfIP)
	var selfIPs []net.IP
	if selfIP != nil {
		selfIPs = []net.IP{selfIP}
	}
	res := resolver.NewResolver(upstreamEndpoints, selfIPs)
	res.SystemFallback = cfg.DNS.SystemFallback
	resolverForQUIC := &resolverAdapter{r: res}

	// Connection tracker for health checks.
	ct := &gateway.ConnectionTracker{}
	var metrics gateway.MetricsCollector

	// Camouflage.
	theme := cfg.Camouflage.Theme
	if theme == "" {
		theme = "minimal"
	}
	gen := web.NewGenerator(theme, cfg.Camouflage.Seed, cfg.Camouflage.SiteName)
	webHandler := web.NewHandler(gen)

	gatewayTLS, err := loadServerTLSRuntime(ctx, cfg, "gateway")
	if err != nil {
		if cfg.Certs.Mode == "acme" {
			return nil, fmt.Errorf("load gateway tls runtime: %w", err)
		}
		slog.Warn("gateway_tls_load_failed", "err", err)
		gatewayTLS = &serverTLSRuntime{Config: &tls.Config{}}
	}
	shutdownFns = append(shutdownFns, gatewayTLS.ShutdownFns...)

	camo := &gateway.Camouflage{
		TLSConfig: gatewayTLS.Config,
		Handler:   webHandler,
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("gateway listen %s: %w", listen, err)
	}
	cleanupGatewayStartup := func() {
		cleanupFns := append([]func(context.Context) error{}, shutdownFns...)
		cleanupFns = append(cleanupFns, func(_ context.Context) error {
			return ln.Close()
		})
		cleanupModeStartup(cleanupFns)
	}

	if cfg.Node.Controller != "" {
		if cfg.Node.ID == "" {
			cleanupGatewayStartup()
			return nil, fmt.Errorf("node.id is required when node.controller is configured")
		}

		nodeCreds, err := loadGRPCMTLSClientCredentials(
			cfg.Node.MTLS.CACert,
			cfg.Node.MTLS.ClientCert,
			cfg.Node.MTLS.ClientKey,
		)
		if err != nil {
			cleanupGatewayStartup()
			return nil, fmt.Errorf("load node mTLS: %w", err)
		}

		syncClient := node.NewSyncClient(node.SyncClientConfig{
			NodeID:     cfg.Node.ID,
			Target:     cfg.Node.Controller,
			Creds:      nodeCreds,
			Hot:        hot,
			CachePath:  cfg.Node.CachePath,
			PublicName: echPublicName(cfg),
			OnRouting: func(update *pb.RoutingConfig) error {
				if routingState == nil {
					return nil
				}
				return routingState.Apply(update)
			},
		})
		if err := syncClient.LoadCache(); err != nil {
			cleanupGatewayStartup()
			return nil, fmt.Errorf("load config cache: %w", err)
		}
		syncClient.Start()
		shutdownFns = append(shutdownFns, func(_ context.Context) error {
			syncClient.Stop()
			return nil
		})

		reporter := gateway.NewReporter(gateway.ReporterConfig{
			NodeID: cfg.Node.ID,
			Target: cfg.Node.Controller,
			Creds:  nodeCreds,
		})
		reporter.Start()
		shutdownFns = append(shutdownFns, func(_ context.Context) error {
			reporter.Stop()
			return nil
		})
		metrics = newGatewayMetricsCollector(reporter)
	} else {
		metrics = newGatewayMetricsCollector(nil)
	}

	ks := hot.KeySet()
	if ks == nil {
		ks, err = waitForRuntimeKeySet(ctx, hot, 5*time.Second)
		if err != nil {
			cleanupGatewayStartup()
			return nil, fmt.Errorf("wait for ECH keys: %w", err)
		}
	}

	srv := &gateway.Server{
		Listener:     ln,
		KeySet:       ks,
		KeySource:    hot,
		Users:        validator,
		Whitelist:    validator,
		Resolver:     &resolverAdapter{r: res},
		Camouflage:   camo,
		MITM:         newGatewayMITMProxy(mitmRT, hot, validator, validator, &resolverAdapter{r: res}, routingState.Router(), egressClient),
		Metrics:      metrics,
		BaseDomain:   cfg.BaseDomain,
		ConnTracker:  ct,
		Router:       nil,
		EgressClient: egressClient,
		MaxConns:     cfg.Gateway.MaxConns,
	}
	if routingState != nil {
		srv.Router = routingState.Router()
	}

	startedQUIC, stopQUIC, err := startQUICRuntime(cfg, hot, validator, resolverForQUIC, routingState, egressClient)
	if err != nil {
		cleanupGatewayStartup()
		return nil, err
	}
	if startedQUIC {
		shutdownFns = append(shutdownFns, stopQUIC)
	}

	go func() {
		slog.Info("gateway_started", "addr", listen)
		if err := srv.Serve(ctx); err != nil && ctx.Err() == nil {
			slog.Error("gateway_serve_error", "err", err)
		}
	}()

	return &modeResult{
		connTracker: ct,
		shutdownFns: append(shutdownFns,
			func(_ context.Context) error {
				return ln.Close()
			},
		),
	}, nil
}

// --- Egress mode ---

func startEgress(ctx context.Context, cfg *PrismConfig) (*modeResult, error) {
	listen := cfg.Egress.Listen
	if listen == "" {
		listen = ":9443"
	}

	al, err := egress.NewAllowlist(cfg.Egress.StaticAllowIPs, cfg.Egress.StaticAllowCIDRs)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist: %w", err)
	}

	srv := &egress.Server{
		Allowlist:          al,
		DenyPrivateTargets: cfg.Egress.DenyPrivateTargets,
	}
	srv.TLSConfig, err = loadMTLSServerTLSConfig(
		cfg.Node.MTLS.CACert,
		cfg.Node.MTLS.ClientCert,
		cfg.Node.MTLS.ClientKey,
	)
	if err != nil {
		return nil, fmt.Errorf("load egress mTLS: %w", err)
	}

	var shutdownFns []func(ctx context.Context) error
	if cfg.Node.Controller != "" {
		if cfg.Node.ID == "" {
			return nil, fmt.Errorf("node.id is required when node.controller is configured")
		}

		hot := appconfig.NewHotConfig()
		hot.SwapEgressIPs(&appconfig.EgressIPConfig{
			IPs:   append([]string(nil), cfg.Egress.StaticAllowIPs...),
			CIDRs: append([]string(nil), cfg.Egress.StaticAllowCIDRs...),
		})

		nodeCreds, err := loadGRPCMTLSClientCredentials(
			cfg.Node.MTLS.CACert,
			cfg.Node.MTLS.ClientCert,
			cfg.Node.MTLS.ClientKey,
		)
		if err != nil {
			return nil, fmt.Errorf("load node mTLS: %w", err)
		}

		syncClient := node.NewSyncClient(node.SyncClientConfig{
			NodeID:     cfg.Node.ID,
			Target:     cfg.Node.Controller,
			Creds:      nodeCreds,
			Hot:        hot,
			CachePath:  cfg.Node.CachePath,
			PublicName: echPublicName(cfg),
			OnEgressIPs: func(current *appconfig.EgressIPConfig) error {
				return al.Reload(current.IPs, current.CIDRs)
			},
		})
		if err := syncClient.LoadCache(); err != nil {
			return nil, fmt.Errorf("load config cache: %w", err)
		}
		syncClient.Start()
		shutdownFns = append(shutdownFns, func(_ context.Context) error {
			syncClient.Stop()
			return nil
		})
	}

	go func() {
		slog.Info("egress_started", "addr", listen)
		if err := srv.ListenAndServe(listen); err != nil && ctx.Err() == nil {
			slog.Error("egress_serve_error", "err", err)
		}
	}()

	return &modeResult{
		shutdownFns: append(shutdownFns,
			func(_ context.Context) error {
				return srv.Close()
			},
		),
	}, nil
}

// --- Client mode ---

func startClient(ctx context.Context, cfg *PrismConfig) (*modeResult, error) {
	dnsListen := cfg.Client.DNSListen
	if dnsListen == "" {
		dnsListen = "127.0.0.1:10053"
	}
	tlsListen := cfg.Client.TLSListen
	if tlsListen == "" {
		tlsListen = "127.0.0.1:10443"
	}
	gwAddr := cfg.Client.Gateway
	if gwAddr == "" {
		gwAddr = cfg.BaseDomain + ":443"
	}

	// ECH encryptor — needs the gateway's ECH public key.
	// For minimal startup without a pre-fetched ECHConfig, we create
	// a placeholder encryptor. Real deployment loads from the DoH URL.
	var enc *ech.Encryptor
	if cfg.ECH.KeyPath != "" {
		ks, err := ech.LoadKeySet(cfg.ECH.KeyPath, cfg.ECH.PublicName)
		if err == nil {
			enc, err = ech.NewEncryptor(ks.Current.Config)
			if err != nil {
				slog.Warn("client_encryptor_init_failed", "err", err)
			}
		} else {
			slog.Warn("client_keyset_load_failed", "err", err)
		}
	}

	if enc == nil {
		return nil, fmt.Errorf("client mode requires ech.key_path to build encryptor")
	}

	localDNS := client.NewLocalDNS(dnsListen)
	proxy := client.NewProxy(tlsListen, gwAddr, enc)

	go func() {
		if err := localDNS.Serve(ctx); err != nil && ctx.Err() == nil {
			slog.Error("client_dns_error", "err", err)
		}
	}()

	go func() {
		slog.Info("client_started", "dns", dnsListen, "tls", tlsListen, "gateway", gwAddr)
		if err := proxy.Serve(ctx); err != nil && ctx.Err() == nil {
			slog.Error("client_proxy_error", "err", err)
		}
	}()

	return &modeResult{
		shutdownFns: []func(ctx context.Context) error{
			func(_ context.Context) error {
				localDNS.Close()
				return proxy.Close()
			},
		},
	}, nil
}

// --- Standalone mode ---

func startStandalone(ctx context.Context, cfg *PrismConfig) (*modeResult, error) {
	listen := cfg.Gateway.ListenTCP
	if listen == "" {
		listen = ":443"
	}

	hot, err := loadLocalHotConfig(cfg)
	if err != nil {
		return nil, err
	}
	allowLegacyHexUsers := cfg.Node.Controller == "" && cfg.Standalone.AllowLegacyHexUsers
	validator := newRuntimeValidator(hot, allowLegacyHexUsers)
	mitmRT, err := loadMITMRuntime(cfg)
	if err != nil {
		return nil, fmt.Errorf("load mitm runtime: %w", err)
	}

	var routingCfg *pb.RoutingConfig
	if cfg.RoutingPath != "" {
		routingCfg, err = egress.LoadRoutingFile(cfg.RoutingPath)
		if err != nil {
			return nil, fmt.Errorf("load routing: %w", err)
		}
	}

	var routingState *routingRuntime
	if routingCfg != nil || cfg.Node.Controller != "" {
		routingState, err = newRoutingRuntime(cfg.GeoIPDBPath, routingCfg)
		if err != nil {
			return nil, fmt.Errorf("init routing runtime: %w", err)
		}
	}

	needEgressClient := cfg.Node.Controller != "" || egress.HasRemoteNodes(routingCfg)
	var egressClient *egress.Client
	if needEgressClient {
		nodeTLS, err := loadMTLSClientTLSConfig(
			cfg.Node.MTLS.CACert,
			cfg.Node.MTLS.ClientCert,
			cfg.Node.MTLS.ClientKey,
		)
		if err != nil {
			if routingState != nil {
				routingState.Close()
			}
			return nil, fmt.Errorf("load node mTLS: %w", err)
		}
		egressClient = &egress.Client{TLSConfig: nodeTLS}
	}

	// Upstream.
	endpoints := []string{cfg.DNS.UpstreamDoH}
	if cfg.DNS.UpstreamDoHFallback != "" {
		endpoints = append(endpoints, cfg.DNS.UpstreamDoHFallback)
	}
	if len(endpoints) == 0 || endpoints[0] == "" {
		endpoints = []string{"https://1.1.1.1/dns-query"}
	}
	upstream := prismdns.NewUpstream(endpoints)

	// Resolver.
	selfIP := net.ParseIP(cfg.SelfIP)
	var selfIPs []net.IP
	if selfIP != nil {
		selfIPs = []net.IP{selfIP}
	}
	res := resolver.NewResolver(endpoints, selfIPs)
	resolverForQUIC := &resolverAdapter{r: res}

	// Camouflage.
	theme := cfg.Camouflage.Theme
	if theme == "" {
		theme = "minimal"
	}
	gen := web.NewGenerator(theme, cfg.Camouflage.Seed, cfg.Camouflage.SiteName)
	webHandler := web.NewHandler(gen)

	// TLS config for DoH.
	dohTLS, err := loadServerTLSRuntime(ctx, cfg, "doh")
	if err != nil {
		if cfg.Certs.Mode == "acme" {
			if routingState != nil {
				routingState.Close()
			}
			return nil, fmt.Errorf("load standalone DoH tls runtime: %w", err)
		}
		slog.Warn("standalone_doh_tls_load_failed", "err", err)
		dohTLS = &serverTLSRuntime{Config: &tls.Config{}}
	}

	// TLS config for gateway camouflage.
	gatewayTLS, err := loadServerTLSRuntime(ctx, cfg, "gateway")
	if err != nil {
		if cfg.Certs.Mode == "acme" {
			if routingState != nil {
				routingState.Close()
			}
			return nil, fmt.Errorf("load standalone gateway tls runtime: %w", err)
		}
		slog.Warn("standalone_gw_tls_load_failed", "err", err)
		gatewayTLS = &serverTLSRuntime{Config: &tls.Config{}}
	}

	// DNS handler chain.
	echCache := prismdns.NewECHCache()
	gwIP := net.ParseIP(cfg.SelfIP)
	if gwIP == nil {
		gwIP = net.ParseIP("127.0.0.1")
	}
	injector := &prismdns.ECHInjector{
		Whitelist:  validator,
		ECHCache:   echCache,
		GatewayIP:  gwIP,
		Upstream:   upstream,
		KeySet:     hot.KeySet(),
		KeySource:  hot,
		BaseDomain: cfg.BaseDomain,
	}
	limiter, cleanupFreq, rateLimitEnabled, err := buildRateLimiter(cfg)
	if err != nil {
		if routingState != nil {
			routingState.Close()
		}
		return nil, fmt.Errorf("build standalone rate limiter: %w", err)
	}
	tokens := prismdns.TokenValidator(nil)
	if bearerTokensEnabled(cfg) {
		tokens = validator
	}
	dohHandler := &prismdns.DoHHandler{
		Camouflage:   webHandler,
		Users:        validator,
		Tokens:       tokens,
		Limiter:      limiter,
		QueryHandler: injector,
		PathPrefix:   "/dns-query/",
	}

	// Connection tracker.
	ct := &gateway.ConnectionTracker{}
	var metrics gateway.MetricsCollector
	var shutdownFns []func(ctx context.Context) error

	camo := &gateway.Camouflage{
		TLSConfig: gatewayTLS.Config,
		Handler:   webHandler,
	}

	if routingState != nil {
		shutdownFns = append(shutdownFns, func(_ context.Context) error {
			return routingState.Close()
		})
	}
	shutdownFns = append(shutdownFns, dohTLS.ShutdownFns...)
	shutdownFns = append(shutdownFns, gatewayTLS.ShutdownFns...)

	if cfg.Node.Controller != "" {
		if cfg.Node.ID == "" {
			cleanupModeStartup(shutdownFns)
			return nil, fmt.Errorf("node.id is required when node.controller is configured")
		}

		nodeCreds, err := loadGRPCMTLSClientCredentials(
			cfg.Node.MTLS.CACert,
			cfg.Node.MTLS.ClientCert,
			cfg.Node.MTLS.ClientKey,
		)
		if err != nil {
			cleanupModeStartup(shutdownFns)
			return nil, fmt.Errorf("load node mTLS: %w", err)
		}

		syncClient := node.NewSyncClient(node.SyncClientConfig{
			NodeID:     cfg.Node.ID,
			Target:     cfg.Node.Controller,
			Creds:      nodeCreds,
			Hot:        hot,
			CachePath:  cfg.Node.CachePath,
			PublicName: echPublicName(cfg),
			OnRouting: func(update *pb.RoutingConfig) error {
				if routingState == nil {
					return nil
				}
				return routingState.Apply(update)
			},
			OnECHKeys: func(*ech.KeySet) error {
				echCache.Clear()
				return nil
			},
		})
		if err := syncClient.LoadCache(); err != nil {
			cleanupModeStartup(shutdownFns)
			return nil, fmt.Errorf("load config cache: %w", err)
		}
		syncClient.Start()
		shutdownFns = append(shutdownFns, func(_ context.Context) error {
			syncClient.Stop()
			return nil
		})

		reporter := gateway.NewReporter(gateway.ReporterConfig{
			NodeID: cfg.Node.ID,
			Target: cfg.Node.Controller,
			Creds:  nodeCreds,
		})
		reporter.Start()
		shutdownFns = append(shutdownFns, func(_ context.Context) error {
			reporter.Stop()
			return nil
		})
		metrics = newGatewayMetricsCollector(reporter)

		auditor := prismdns.NewAuditor(prismdns.AuditorConfig{
			NodeID: cfg.Node.ID,
			Target: cfg.Node.Controller,
			Creds:  nodeCreds,
		})
		auditor.Start()
		shutdownFns = append(shutdownFns, func(_ context.Context) error {
			auditor.Stop()
			return nil
		})
		dohHandler.Auditor = auditor
	} else {
		metrics = newGatewayMetricsCollector(nil)
	}

	ks := hot.KeySet()
	if ks == nil {
		ks, err = waitForRuntimeKeySet(ctx, hot, 5*time.Second)
		if err != nil {
			cleanupModeStartup(shutdownFns)
			return nil, fmt.Errorf("wait for ECH keys: %w", err)
		}
	}

	// Gateway server (does not own a listener in standalone mode).
	gwSrv := &gateway.Server{
		KeySet:       ks,
		KeySource:    hot,
		Users:        validator,
		Whitelist:    validator,
		Resolver:     &resolverAdapter{r: res},
		Camouflage:   camo,
		MITM:         newGatewayMITMProxy(mitmRT, hot, validator, validator, &resolverAdapter{r: res}, routingState.Router(), egressClient),
		Metrics:      metrics,
		BaseDomain:   cfg.BaseDomain,
		ConnTracker:  ct,
		EgressClient: egressClient,
	}
	if routingState != nil {
		gwSrv.Router = routingState.Router()
	}

	startedQUIC, stopQUIC, err := startQUICRuntime(cfg, hot, validator, resolverForQUIC, routingState, egressClient)
	if err != nil {
		cleanupModeStartup(shutdownFns)
		return nil, err
	}
	if startedQUIC {
		injector.AdvertiseHTTP3 = !mitmRT.Enabled
		shutdownFns = append(shutdownFns, stopQUIC)
	}

	// Shared listener.
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		cleanupModeStartup(shutdownFns)
		return nil, fmt.Errorf("standalone listen %s: %w", listen, err)
	}

	ss := &appconfig.StandaloneServer{
		Listener:   ln,
		DNSHandler: dohHandler,
		Gateway:    gwSrv,
		BaseDomain: cfg.BaseDomain,
		TLSConfig:  dohTLS.Config,
	}
	if rateLimitEnabled {
		limiter.Start(cleanupFreq)
		shutdownFns = append(shutdownFns, func(context.Context) error {
			limiter.Stop()
			return nil
		})
	}

	go func() {
		slog.Info("standalone_started", "addr", listen, "base_domain", cfg.BaseDomain)
		if err := ss.Serve(ctx); err != nil && ctx.Err() == nil {
			slog.Error("standalone_serve_error", "err", err)
		}
	}()

	shutdownFns = append(shutdownFns,
		func(_ context.Context) error {
			return ln.Close()
		},
	)

	// File watcher for hot-reloading local config in standalone-without-controller mode.
	if cfg.Node.Controller == "" {
		if watchFiles := buildWatchFiles(cfg); len(watchFiles) > 0 {
			w, err := router.NewWatcher(router.WatcherConfig{
				Files:    watchFiles,
				OnReload: router.ReloadConfigFile(buildWatchReloadHandlers(cfg, hot, routingState, echCache)),
			})
			if err != nil {
				slog.Warn("watcher_init_failed", "err", err)
			} else {
				w.Start(ctx)
				shutdownFns = append(shutdownFns, func(_ context.Context) error {
					w.Stop()
					return nil
				})
			}
		}
	}

	return &modeResult{
		connTracker: ct,
		shutdownFns: shutdownFns,
	}, nil
}

// --- Helpers ---

// buildWatchFiles returns the list of config file paths to watch for changes.
func buildWatchFiles(cfg *PrismConfig) []string {
	var files []string
	if cfg.UsersPath != "" {
		files = append(files, cfg.UsersPath)
	}
	if cfg.WhitelistPath != "" {
		files = append(files, cfg.WhitelistPath)
	}
	if cfg.RoutingPath != "" {
		files = append(files, cfg.RoutingPath)
	}
	if cfg.ECH.KeyPath != "" {
		files = append(files, cfg.ECH.KeyPath)
	}
	return files
}

func newGatewayMITMProxy(rt *mitmRuntime, keySource gateway.ECHKeySource, users gateway.UserMatcher, whitelist gateway.WhitelistChecker, resolver gateway.Resolver, router *egress.Router, egressClient *egress.Client) gateway.MITMProxy {
	if rt == nil || !rt.Enabled || rt.Issuer == nil {
		return nil
	}

	var upstream gateway.MITMUpstream = &gateway.UpstreamDialer{
		Resolver:   resolver,
		MinVersion: rt.UpstreamMinVersion,
	}
	if router != nil {
		upstream = &gateway.RoutedUpstreamDialer{
			UpstreamDialer: gateway.UpstreamDialer{
				Resolver:   resolver,
				MinVersion: rt.UpstreamMinVersion,
			},
			Router:       router,
			TunnelOpener: egressClient,
		}
	}
	return &gateway.DirectMITMProxy{
		KeySource: keySource,
		Users:     users,
		Whitelist: whitelist,
		Issuer:    rt.Issuer,
		Upstream:  upstream,
	}
}

func buildWatchReloadHandlers(cfg *PrismConfig, hot *appconfig.HotConfig, routing *routingRuntime, echCache *prismdns.ECHCache) map[string]func(string) error {
	handlers := make(map[string]func(string) error)

	if cfg.UsersPath != "" {
		handlers[filepath.Base(cfg.UsersPath)] = func(path string) error {
			reg, err := router.LoadUsersFile(path, userSalt)
			if err != nil {
				return err
			}
			hot.SwapUsers(reg)
			slog.Info("users_hot_reloaded", "path", path, "count", len(reg.All()))
			return nil
		}
	}

	if cfg.WhitelistPath != "" {
		handlers[filepath.Base(cfg.WhitelistPath)] = func(path string) error {
			wl, err := loadWhitelistFromFile(path)
			if err != nil {
				return err
			}
			hot.SwapWhitelist(wl)
			slog.Info("whitelist_hot_reloaded", "path", path, "count", len(wl.Domains()))
			return nil
		}
	}

	if cfg.RoutingPath != "" && routing != nil {
		handlers[filepath.Base(cfg.RoutingPath)] = func(path string) error {
			cfg, err := egress.LoadRoutingFile(path)
			if err != nil {
				return err
			}
			if err := routing.Apply(cfg); err != nil {
				return err
			}
			slog.Info("routing_hot_reloaded", "path", path, "rules", len(cfg.GetRules()))
			return nil
		}
	}

	if cfg.ECH.KeyPath != "" {
		handlers[filepath.Base(cfg.ECH.KeyPath)] = func(path string) error {
			var (
				ks  *ech.KeySet
				err error
			)
			if hot.KeySet() != nil {
				ks, err = ech.RotateKeySet(hot.KeySet(), path, echPublicName(cfg))
			} else {
				ks, err = ech.LoadKeySet(path, echPublicName(cfg))
			}
			if err != nil {
				return err
			}
			hot.SwapKeySet(ks)
			if echCache != nil {
				echCache.Clear()
			}
			slog.Info("ech_keys_hot_reloaded", "path", path, "has_previous", ks.Previous != nil)
			return nil
		}
	}

	return handlers
}

// resolverAdapter wraps resolver.Resolver to satisfy gateway.Resolver interface.
type resolverAdapter struct {
	r *resolver.Resolver
}

func (a *resolverAdapter) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	result, err := a.r.Resolve(ctx, domain)
	if err != nil {
		return nil, err
	}
	return result.IPs, nil
}

func startQUICRuntime(
	cfg *PrismConfig,
	hot *appconfig.HotConfig,
	validator *runtimeValidator,
	res *resolverAdapter,
	routingState *routingRuntime,
	egressClient *egress.Client,
) (bool, func(context.Context) error, error) {
	if cfg.Gateway.ListenUDP == "" {
		return false, nil, nil
	}

	udpConn, err := net.ListenPacket("udp", cfg.Gateway.ListenUDP)
	if err != nil {
		return false, nil, fmt.Errorf("gateway udp listen %s: %w", cfg.Gateway.ListenUDP, err)
	}

	handler := prismquic.NewHandler(udpConn, hot.KeySet(), validator, validator, cfg.BaseDomain)
	handler.KeySource = hot
	handler.Resolver = res
	if routingState != nil {
		handler.Router = routingState.Router()
	}
	if egressClient != nil {
		handler.EgressClient = &egress.QUICClient{TLSConfig: egressClient.TLSConfig}
	}

	go func() {
		slog.Info("quic_runtime_started", "addr", cfg.Gateway.ListenUDP)
		if err := handler.Serve(); err != nil {
			slog.Error("quic_runtime_error", "addr", cfg.Gateway.ListenUDP, "err", err)
		}
	}()

	return true, func(context.Context) error {
		handler.Stop()
		return nil
	}, nil
}

func cleanupModeStartup(shutdownFns []func(context.Context) error) {
	if len(shutdownFns) == 0 {
		return
	}
	gracefulShutdown(shutdownFns, 5*time.Second)
}

// loadKeySet loads the ECH keyset from config.
func loadKeySet(cfg *PrismConfig) (*ech.KeySet, error) {
	if cfg.ECH.KeyPath == "" {
		return nil, fmt.Errorf("ech.key_path is required")
	}
	return ech.LoadKeySet(cfg.ECH.KeyPath, echPublicName(cfg))
}

// loadTLSConfig creates a CertReloader-backed tls.Config that auto-reloads
// on file mtime changes. The poll interval is 30s.
func loadTLSConfig(ctx context.Context, certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("cert and key paths required")
	}
	cr, err := certs.NewCertReloader(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	go cr.WatchMtime(ctx, 30*time.Second)
	return cr.TLSConfig(), nil
}

func loadGRPCMTLSServerCredentials(caFile, certFile, keyFile string) (credentials.TransportCredentials, error) {
	tlsCfg, err := loadMTLSServerTLSConfig(caFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(tlsCfg), nil
}

func loadMTLSServerTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	if caFile == "" || certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("ca, cert, and key paths required")
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return mtls.ServerTLSConfig(caPEM, certPEM, keyPEM)
}

func loadWhitelistFromFile(path string) (*appconfig.Whitelist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wlCfg WhitelistConfig
	if err := yaml.Unmarshal(data, &wlCfg); err != nil {
		return nil, err
	}
	return appconfig.NewWhitelist(wlCfg.Domains), nil
}

// userSalt is the salt used for user hash computation, matching the controller.
const userSalt = "prism"

// isValidHexHash checks if s is a 12-character lowercase hex string.
func isValidHexHash(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
