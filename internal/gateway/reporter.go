package gateway

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

// Reporter collects ConnMetrics from the gateway and streams them to the
// Controller as TrafficBatch via gRPC. It flushes every flushInterval or
// when batchSize records accumulate. On send failure, records are discarded
// (no retry, to prevent OOM).
type Reporter struct {
	nodeID        string
	target        string
	creds         credentials.TransportCredentials
	batchSize     int
	flushInterval time.Duration

	mu      sync.Mutex
	pending []*pb.TrafficRecord

	connMu sync.Mutex
	conn   *grpc.ClientConn

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// ReporterConfig holds constructor parameters.
type ReporterConfig struct {
	NodeID        string
	Target        string // controller address host:port
	Creds         credentials.TransportCredentials
	BatchSize     int           // default 100
	FlushInterval time.Duration // default 10s
}

// NewReporter creates a Reporter. Call Start() to begin background streaming.
func NewReporter(cfg ReporterConfig) *Reporter {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	return &Reporter{
		nodeID:        cfg.NodeID,
		target:        cfg.Target,
		creds:         cfg.Creds,
		batchSize:     cfg.BatchSize,
		flushInterval: cfg.FlushInterval,
	}
}

// RecordConn implements MetricsCollector. Thread-safe.
func (r *Reporter) RecordConn(m *ConnMetrics) {
	egressLabel := m.Egress
	if egressLabel == "" {
		egressLabel = m.TrafficType // fallback for non-ECH traffic
	}
	rec := &pb.TrafficRecord{
		UserId:     m.UserID,
		Domain:     m.InnerSNI,
		ClientIp:   m.RemoteAddr,
		Egress:     egressLabel,
		BytesUp:    m.UpBytes,
		BytesDown:  m.DownBytes,
		StartTime:  m.StartTime.Unix(),
		EndTime:    m.EndTime.Unix(),
		EchSuccess: m.ECHSuccess,
		ErrorType:  m.ErrorType,
	}

	r.mu.Lock()
	r.pending = append(r.pending, rec)
	shouldFlush := len(r.pending) >= r.batchSize
	r.mu.Unlock()

	if shouldFlush {
		r.flushAsync()
	}
}

// Start begins the background flush loop.
func (r *Reporter) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Add(1)
	go r.flushLoop(ctx)
}

// Stop stops the background loop and flushes remaining records.
func (r *Reporter) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	r.closeConn()
}

func (r *Reporter) flushLoop(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(r.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.flush(ctx)
		case <-ctx.Done():
			// Final flush attempt with a short deadline.
			finalCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			r.flush(finalCtx)
			cancel()
			return
		}
	}
}

func (r *Reporter) flushAsync() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		r.flush(ctx)
	}()
}

func (r *Reporter) flush(ctx context.Context) {
	r.mu.Lock()
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return
	}
	batch := r.pending
	r.pending = nil
	r.mu.Unlock()

	if err := r.send(ctx, batch); err != nil {
		// Discard on failure — no retry to prevent OOM.
		slog.Warn("traffic_report_failed", "records", len(batch), "err", err)
	} else {
		slog.Debug("traffic_report_sent", "records", len(batch))
	}
}

func (r *Reporter) send(ctx context.Context, records []*pb.TrafficRecord) error {
	conn, err := r.getConn()
	if err != nil {
		return err
	}

	client := pb.NewNodeReportClient(conn)
	stream, err := client.ReportTraffic(ctx)
	if err != nil {
		// Connection may be stale; close and retry once.
		r.closeConn()
		conn, err = r.getConn()
		if err != nil {
			return err
		}
		client = pb.NewNodeReportClient(conn)
		stream, err = client.ReportTraffic(ctx)
		if err != nil {
			return err
		}
	}

	err = stream.Send(&pb.TrafficBatch{
		NodeId:  r.nodeID,
		Records: records,
	})
	if err != nil {
		return err
	}

	_, err = stream.CloseAndRecv()
	return err
}

func (r *Reporter) getConn() (*grpc.ClientConn, error) {
	r.connMu.Lock()
	defer r.connMu.Unlock()

	if r.conn != nil {
		return r.conn, nil
	}

	if r.creds == nil {
		return nil, fmt.Errorf("gateway reporter requires mTLS credentials")
	}

	opts := []grpc.DialOption{grpc.WithTransportCredentials(r.creds)}
	conn, err := grpc.NewClient(r.target, opts...)
	if err != nil {
		return nil, err
	}
	r.conn = conn
	return conn, nil
}

func (r *Reporter) closeConn() {
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if r.conn != nil {
		r.conn.Close()
		r.conn = nil
	}
}

// PendingCount returns the number of records waiting to be flushed.
func (r *Reporter) PendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}
