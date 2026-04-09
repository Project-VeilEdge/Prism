//go:build !linux

// Package relay provides bidirectional TCP relay with metrics and buffer pooling.
// This file provides the non-Linux fallback for SpliceRelay, using io.CopyBuffer
// with pooled buffers from pkg/pool.
package relay

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"prism/pkg/pool"
)

// SpliceRelay performs bidirectional relay between two TCP connections.
// On non-Linux platforms, this is equivalent to the standard io.CopyBuffer relay
// using pooled 16KB buffers.
//
// upBytes/downBytes atomically accumulate transferred byte counts.
func SpliceRelay(client, upstream net.Conn, upBytes, downBytes *atomic.Int64, lastActivity *atomic.Int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	// client → upstream (upload)
	go func() {
		defer wg.Done()
		buf := pool.GetRelayBuf()
		defer pool.PutRelayBuf(buf)
		n, _ := io.CopyBuffer(&activityWriter{conn: upstream, lastActivity: lastActivity}, client, *buf)
		upBytes.Add(n)
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// upstream → client (download)
	go func() {
		defer wg.Done()
		buf := pool.GetRelayBuf()
		defer pool.PutRelayBuf(buf)
		n, _ := io.CopyBuffer(&activityWriter{conn: client, lastActivity: lastActivity}, upstream, *buf)
		downBytes.Add(n)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Idle timeout watchdog using atomic timestamp (safe for concurrent access).
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

// activityWriter wraps a net.Conn and updates lastActivity on each write.
type activityWriter struct {
	conn         net.Conn
	lastActivity *atomic.Int64
}

func (w *activityWriter) Write(b []byte) (int, error) {
	n, err := w.conn.Write(b)
	if n > 0 && w.lastActivity != nil {
		w.lastActivity.Store(time.Now().UnixNano())
	}
	return n, err
}
