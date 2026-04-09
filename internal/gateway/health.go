package gateway

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// HealthHandler serves the /health endpoint for gateway health checks.
// It reports the current status and active connection count.
type HealthHandler struct {
	connections *atomic.Int64
	server      *http.Server
}

// HealthResponse is the JSON body returned by /health.
type HealthResponse struct {
	Status      string `json:"status"`
	Connections int64  `json:"connections"`
}

// NewHealthHandler creates a health handler that reads the active connection
// count from the provided atomic counter.
func NewHealthHandler(connections *atomic.Int64) *HealthHandler {
	if connections == nil {
		connections = &atomic.Int64{}
	}
	h := &HealthHandler{connections: connections}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.serveHealth)

	h.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	return h
}

// ListenAndServe starts the health check HTTP server on the given address.
// Typically called with ":8080".
func (h *HealthHandler) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	slog.Info("health_endpoint_started", "addr", addr)
	return h.server.Serve(ln)
}

// Shutdown gracefully shuts down the health server.
func (h *HealthHandler) Shutdown(ctx context.Context) error {
	return h.server.Shutdown(ctx)
}

func (h *HealthHandler) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	resp := HealthResponse{
		Status:      "ok",
		Connections: h.connections.Load(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// ConnectionTracker is a helper that increments/decrements an atomic counter.
// Use Add(1) on accept, Add(-1) on close.
type ConnectionTracker struct {
	active atomic.Int64
}

// Add adjusts the active connection count by delta (+1 or -1).
func (ct *ConnectionTracker) Add(delta int64) {
	ct.active.Add(delta)
}

// Count returns the current active connection count.
func (ct *ConnectionTracker) Count() int64 {
	return ct.active.Load()
}

// Pointer returns the underlying atomic.Int64 for use with HealthHandler.
func (ct *ConnectionTracker) Pointer() *atomic.Int64 {
	return &ct.active
}
