// Package relay provides bidirectional TCP relay with metrics and buffer pooling.
package relay

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"prism/pkg/pool"
)

// CountingWriter wraps a net.Conn and counts bytes written through it.
// It also touches an atomic timestamp on every write, enabling idle-timeout detection.
type CountingWriter struct {
	conn         net.Conn
	bytes        atomic.Int64
	lastActivity *atomic.Int64 // unix nanos, shared between up/down writers
}

// NewCountingWriter creates a CountingWriter around conn.
// lastActivity is optional — if non-nil, it is updated on each Write.
func NewCountingWriter(conn net.Conn, lastActivity *atomic.Int64) *CountingWriter {
	return &CountingWriter{
		conn:         conn,
		lastActivity: lastActivity,
	}
}

// Write writes b to the underlying connection and updates the byte counter.
func (cw *CountingWriter) Write(b []byte) (int, error) {
	n, err := cw.conn.Write(b)
	if n > 0 {
		cw.bytes.Add(int64(n))
		if cw.lastActivity != nil {
			cw.lastActivity.Store(time.Now().UnixNano())
		}
	}
	return n, err
}

// Bytes returns the total number of bytes written.
func (cw *CountingWriter) Bytes() int64 {
	return cw.bytes.Load()
}

const (
	// IdleTimeout is the bidirectional idle timeout. If neither direction
	// transfers data for this duration, the relay is terminated.
	IdleTimeout = 5 * time.Minute
)

// RelayWithMetrics performs bidirectional relay between client and upstream
// using pooled 16KB buffers from pkg/pool.
//
// It writes initial buffered bytes (from the classification phase) to upstream
// before starting the bidirectional copy. An idle timer closes both connections
// if no data flows in either direction for IdleTimeout.
//
// upCounter counts bytes flowing client→upstream (upload).
// downCounter counts bytes flowing upstream→client (download).
func RelayWithMetrics(client, upstream net.Conn, upCounter, downCounter *CountingWriter) {
	lastActivity := upCounter.lastActivity // shared atomic

	var wg sync.WaitGroup
	wg.Add(2)

	// client → upstream (upload)
	go func() {
		defer wg.Done()
		buf := pool.GetRelayBuf()
		defer pool.PutRelayBuf(buf)
		io.CopyBuffer(upCounter, client, *buf)
		// Half-close: signal upstream that client is done sending.
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// upstream → client (download)
	go func() {
		defer wg.Done()
		buf := pool.GetRelayBuf()
		defer pool.PutRelayBuf(buf)
		io.CopyBuffer(downCounter, upstream, *buf)
		// Half-close: signal client that upstream is done sending.
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Idle timeout watchdog using atomic timestamp (no concurrent timer.Reset).
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			last := time.Unix(0, lastActivity.Load())
			if time.Since(last) >= IdleTimeout {
				client.Close()
				upstream.Close()
				<-done
				return
			}
		}
	}
}

// NewRelayPair creates a matched pair of CountingWriters with a shared
// lastActivity timestamp suitable for passing to RelayWithMetrics.
// upWriter writes to upstream (counts upload bytes).
// downWriter writes to client (counts download bytes).
func NewRelayPair(client, upstream net.Conn) (upWriter, downWriter *CountingWriter) {
	lastActivity := &atomic.Int64{}
	lastActivity.Store(time.Now().UnixNano())
	upWriter = NewCountingWriter(upstream, lastActivity)
	downWriter = NewCountingWriter(client, lastActivity)
	return
}
