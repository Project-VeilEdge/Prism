package dns

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pb "prism/api/proto/control"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// AuditRecord represents a single DNS query audit entry.
type AuditRecord struct {
	UserID    string
	Domain    string
	QueryType string
	ClientIP  string
	Timestamp time.Time
}

// Auditor collects DNS query audit records and streams them to the
// Controller as DNSAuditBatch via gRPC. Follows the same batch-and-flush
// pattern as gateway.Reporter: flushes every flushInterval or when
// batchSize records accumulate. On send failure, records are discarded.
type Auditor struct {
	nodeID        string
	target        string
	creds         credentials.TransportCredentials
	batchSize     int
	flushInterval time.Duration

	mu      sync.Mutex
	pending []*pb.DNSAuditRecord

	connMu sync.Mutex
	conn   *grpc.ClientConn

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// AuditorConfig holds constructor parameters for Auditor.
type AuditorConfig struct {
	NodeID        string
	Target        string // controller address host:port
	Creds         credentials.TransportCredentials
	BatchSize     int           // default 100
	FlushInterval time.Duration // default 10s
}

// NewAuditor creates an Auditor. Call Start() to begin background streaming.
func NewAuditor(cfg AuditorConfig) *Auditor {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	return &Auditor{
		nodeID:        cfg.NodeID,
		target:        cfg.Target,
		creds:         cfg.Creds,
		batchSize:     cfg.BatchSize,
		flushInterval: cfg.FlushInterval,
	}
}

// Record adds a DNS audit record. Thread-safe.
func (a *Auditor) Record(rec AuditRecord) {
	pbRec := &pb.DNSAuditRecord{
		UserId:    rec.UserID,
		Domain:    rec.Domain,
		QueryType: rec.QueryType,
		ClientIp:  rec.ClientIP,
		Timestamp: rec.Timestamp.Unix(),
	}

	a.mu.Lock()
	a.pending = append(a.pending, pbRec)
	shouldFlush := len(a.pending) >= a.batchSize
	a.mu.Unlock()

	if shouldFlush {
		a.flushAsync()
	}
}

// Start begins the background flush loop.
func (a *Auditor) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.wg.Add(1)
	go a.flushLoop(ctx)
}

// Stop stops the background loop and flushes remaining records.
func (a *Auditor) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
	a.wg.Wait()
	a.closeConn()
}

func (a *Auditor) flushLoop(ctx context.Context) {
	defer a.wg.Done()
	ticker := time.NewTicker(a.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.flush(ctx)
		case <-ctx.Done():
			finalCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			a.flush(finalCtx)
			cancel()
			return
		}
	}
}

func (a *Auditor) flushAsync() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		a.flush(ctx)
	}()
}

func (a *Auditor) flush(ctx context.Context) {
	a.mu.Lock()
	if len(a.pending) == 0 {
		a.mu.Unlock()
		return
	}
	batch := a.pending
	a.pending = nil
	a.mu.Unlock()

	if err := a.send(ctx, batch); err != nil {
		slog.Warn("dns_audit_report_failed", "records", len(batch), "err", err)
	} else {
		slog.Debug("dns_audit_report_sent", "records", len(batch))
	}
}

func (a *Auditor) send(ctx context.Context, records []*pb.DNSAuditRecord) error {
	conn, err := a.getConn()
	if err != nil {
		return err
	}

	client := pb.NewDNSAuditClient(conn)
	stream, err := client.ReportDNS(ctx)
	if err != nil {
		// Connection may be stale; close and retry once.
		a.closeConn()
		conn, err = a.getConn()
		if err != nil {
			return err
		}
		client = pb.NewDNSAuditClient(conn)
		stream, err = client.ReportDNS(ctx)
		if err != nil {
			return err
		}
	}

	err = stream.Send(&pb.DNSAuditBatch{
		NodeId:  a.nodeID,
		Records: records,
	})
	if err != nil {
		return err
	}

	_, err = stream.CloseAndRecv()
	return err
}

func (a *Auditor) getConn() (*grpc.ClientConn, error) {
	a.connMu.Lock()
	defer a.connMu.Unlock()

	if a.conn != nil {
		return a.conn, nil
	}

	if a.creds == nil {
		return nil, fmt.Errorf("dns auditor requires mTLS credentials")
	}

	opts := []grpc.DialOption{grpc.WithTransportCredentials(a.creds)}
	conn, err := grpc.NewClient(a.target, opts...)
	if err != nil {
		return nil, err
	}
	a.conn = conn
	return conn, nil
}

func (a *Auditor) closeConn() {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}
}

// PendingCount returns the number of records waiting to be flushed.
func (a *Auditor) PendingCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}
