package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"prism/internal/ech"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// version is set at build time via:
//
//	go build -ldflags="-X main.version=v1.0.0" ./cmd/prism
var version = "Dev.0.1.2"

var validModes = map[string]bool{
	"controller": true,
	"dns":        true,
	"gateway":    true,
	"egress":     true,
	"client":     true,
	"standalone": true,
	"keygen":     true,
	"cert":       true,
	"user":       true,
	"query":      true,
	"config":     true,
}

func handleBareSubcommand(args []string, stdout io.Writer) bool {
	if len(args) >= 2 && args[1] == "version" {
		fmt.Fprintln(stdout, version)
		return true
	}
	return false
}

func main() {
	if handleBareSubcommand(os.Args, os.Stdout) {
		return
	}

	mode := flag.String("mode", "", "deployment mode: controller|dns|gateway|egress|client|standalone|keygen")
	configPath := flag.String("config", "configs/prism.yaml", "path to prism.yaml config file")
	keyDir := flag.String("key-dir", "configs", "directory to write generated keys")
	metricsAddr := flag.String("metrics-addr", ":8080", "address for Prometheus metrics and health endpoint")
	flag.Parse()

	if *mode == "" {
		fmt.Fprintln(os.Stderr, "error: --mode is required")
		flag.Usage()
		os.Exit(1)
	}

	if !validModes[*mode] {
		fmt.Fprintf(os.Stderr, "error: unknown mode %q\n", *mode)
		flag.Usage()
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// --- CLI-only modes (no long-running server) ---

	if *mode == "keygen" {
		if err := runKeygen(*keyDir); err != nil {
			slog.Error("keygen_failed", "err", err)
			os.Exit(1)
		}
		return
	}

	if *mode == "cert" {
		if err := runCert(flag.Args()); err != nil {
			slog.Error("cert_failed", "err", err)
			os.Exit(1)
		}
		return
	}

	if *mode == "user" {
		if err := runUser(flag.Args()); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *mode == "query" {
		if err := runQuery(flag.Args()); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *mode == "config" {
		if err := runConfig(flag.Args()); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// --- Long-running server modes ---

	slog.Info("starting", "mode", *mode, "pid", os.Getpid())

	// Create a root context that is canceled on SIGTERM/SIGINT.
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Start Prometheus metrics + health endpoint.
	var activeConns atomic.Int64
	metricsSrv := startMetricsServer(*metricsAddr, &activeConns)

	// Track background services for coordinated shutdown.
	var shutdownFns []func(ctx context.Context) error

	// Register metrics server shutdown.
	shutdownFns = append(shutdownFns, metricsSrv.Shutdown)

	// Load config and dispatch to mode-specific server.
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("config_load_failed", "path", *configPath, "err", err)
		os.Exit(1)
	}

	// Wire log level from config to slog.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.LogLevel),
	})))

	result, err := dispatchMode(ctx, *mode, cfg)
	if err != nil {
		slog.Error("mode_start_failed", "mode", *mode, "err", err)
		cancel()
		gracefulShutdown(shutdownFns, 5*time.Second)
		os.Exit(1)
	}

	shutdownFns = append(shutdownFns, result.shutdownFns...)
	if result.connTracker != nil {
		// Wire the connection tracker into the metrics server's health endpoint.
		activeConns.Store(result.connTracker.Count())
		// Periodically sync the counter (the health endpoint reads activeConns).
		go func() {
			tk := time.NewTicker(time.Second)
			defer tk.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tk.C:
					activeConns.Store(result.connTracker.Count())
				}
			}
		}()
	}

	// Block until signal.
	sig := <-sigCh
	slog.Info("shutdown_signal_received", "signal", sig.String())
	cancel()

	// Graceful shutdown with 30s grace period.
	gracefulShutdown(shutdownFns, 30*time.Second)

	slog.Info("shutdown_complete")
}

// gracefulShutdown runs all shutdown functions concurrently with a deadline.
func gracefulShutdown(shutdownFns []func(ctx context.Context) error, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var wg sync.WaitGroup
	for _, fn := range shutdownFns {
		wg.Add(1)
		go func(shutdown func(ctx context.Context) error) {
			defer wg.Done()
			if err := shutdown(ctx); err != nil {
				if errors.Is(err, net.ErrClosed) {
					slog.Debug("listener_closed", "err", err)
				} else {
					slog.Error("shutdown_error", "err", err)
				}
			}
		}(fn)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("all_services_stopped")
	case <-ctx.Done():
		slog.Warn("shutdown_timeout_exceeded", "timeout", timeout)
	}
}

// startMetricsServer launches the Prometheus metrics and health check HTTP server.
// It serves:
//   - /metrics  — Prometheus scrape endpoint
//   - /health   — health check (returns 200 OK with connection count)
func startMetricsServer(addr string, connections *atomic.Int64) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","connections":%d}`, connections.Load())
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("metrics_listen_failed", "addr", addr, "err", err)
		return srv
	}

	go func() {
		slog.Info("metrics_server_started", "addr", addr)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics_server_error", "err", err)
		}
	}()

	return srv
}

// dispatchMode starts the appropriate server for the given mode.
func dispatchMode(ctx context.Context, mode string, cfg *PrismConfig) (*modeResult, error) {
	switch mode {
	case "controller":
		return startController(ctx, cfg)
	case "dns":
		return startDNS(ctx, cfg)
	case "gateway":
		return startGateway(ctx, cfg)
	case "egress":
		return startEgress(ctx, cfg)
	case "client":
		return startClient(ctx, cfg)
	case "standalone":
		return startStandalone(ctx, cfg)
	default:
		return nil, fmt.Errorf("unknown server mode: %s", mode)
	}
}

func runKeygen(dir string) error {
	kp, err := ech.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	skPath := dir + "/ech-key.pem"
	pkPath := dir + "/ech-pubkey.pem"

	if err := os.WriteFile(skPath, kp.MarshalPrivateKeyPEM(), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pkPath, kp.MarshalPublicKeyPEM(), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	slog.Info("keygen_ok", "private_key", skPath, "public_key", pkPath)
	return nil
}

// parseLogLevel converts a config string to a slog.Level.
func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
