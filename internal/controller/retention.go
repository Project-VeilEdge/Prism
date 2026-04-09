package controller

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// RetentionCleaner periodically deletes old traffic and DNS audit records
// from the store to prevent SQLite file from growing indefinitely.
type RetentionCleaner struct {
	store     Store
	retention time.Duration // how long to keep records (default 30 days)
	interval  time.Duration // how often to run cleanup (default 1 hour)

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// RetentionConfig holds constructor parameters.
type RetentionConfig struct {
	Store     Store
	Retention time.Duration // default 30 days
	Interval  time.Duration // default 1 hour
}

// NewRetentionCleaner creates a RetentionCleaner.
func NewRetentionCleaner(cfg RetentionConfig) *RetentionCleaner {
	if cfg.Retention <= 0 {
		cfg.Retention = 30 * 24 * time.Hour
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Hour
	}
	return &RetentionCleaner{
		store:     cfg.Store,
		retention: cfg.Retention,
		interval:  cfg.Interval,
	}
}

// Start begins the periodic cleanup loop.
func (rc *RetentionCleaner) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	rc.cancel = cancel
	rc.wg.Add(1)
	go rc.loop(ctx)
}

// Stop stops the cleanup loop.
func (rc *RetentionCleaner) Stop() {
	if rc.cancel != nil {
		rc.cancel()
	}
	rc.wg.Wait()
}

// RunOnce executes a single cleanup pass. Exported for testing.
func (rc *RetentionCleaner) RunOnce(ctx context.Context) (trafficDeleted, dnsDeleted int64) {
	cutoff := time.Now().Add(-rc.retention)

	td, err := rc.store.DeleteOldTraffic(ctx, cutoff)
	if err != nil {
		slog.Error("retention_delete_traffic_failed", "err", err)
	} else if td > 0 {
		slog.Info("retention_traffic_cleaned", "deleted", td, "cutoff", cutoff)
	}

	dd, err := rc.store.DeleteOldDNSAudit(ctx, cutoff)
	if err != nil {
		slog.Error("retention_delete_dns_audit_failed", "err", err)
	} else if dd > 0 {
		slog.Info("retention_dns_audit_cleaned", "deleted", dd, "cutoff", cutoff)
	}

	return td, dd
}

func (rc *RetentionCleaner) loop(ctx context.Context) {
	defer rc.wg.Done()
	ticker := time.NewTicker(rc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rc.RunOnce(ctx)
		case <-ctx.Done():
			return
		}
	}
}
