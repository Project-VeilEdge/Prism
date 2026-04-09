//go:build linux

// Package relay provides bidirectional TCP relay with metrics and buffer pooling.
// This file implements Linux splice(2) zero-copy relay between two TCP sockets.
package relay

import (
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"prism/pkg/pool"

	"golang.org/x/sys/unix"
)

const (
	// spliceChunkSize is the maximum number of bytes to splice in one call.
	// 64KB matches the Linux pipe default capacity and avoids partial splices.
	spliceChunkSize = 64 * 1024

	// spliceFlagMore tells the kernel more data is expected (like TCP_CORK).
	spliceFlagMore = unix.SPLICE_F_MOVE | unix.SPLICE_F_MORE | unix.SPLICE_F_NONBLOCK
)

// splicePipePool reuses kernel pipes to amortize pipe creation cost across connections.
var splicePipePool = sync.Pool{
	New: func() any {
		fds := make([]int, 2)
		if err := unix.Pipe2(fds, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
			return nil
		}
		return &pipePair{r: fds[0], w: fds[1]}
	},
}

type pipePair struct {
	r, w int
}

func getPipe() *pipePair {
	v := splicePipePool.Get()
	if v == nil {
		return nil
	}
	return v.(*pipePair)
}

func putPipe(p *pipePair) {
	if p == nil {
		return
	}
	splicePipePool.Put(p)
}

func closePipe(p *pipePair) {
	if p == nil {
		return
	}
	unix.Close(p.r)
	unix.Close(p.w)
}

// SpliceRelay performs zero-copy bidirectional relay between two TCP connections
// using the Linux splice(2) system call. Data flows through a kernel pipe,
// avoiding any user-space buffer copies.
//
// If either connection does not support syscall.Conn (required for raw fd access),
// it falls back to io.CopyBuffer-based relay via fallbackCopyOneDir.
//
// upBytes/downBytes atomically accumulate transferred byte counts.
func SpliceRelay(client, upstream net.Conn, upBytes, downBytes *atomic.Int64, lastActivity *atomic.Int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	// client → upstream (upload)
	go func() {
		defer wg.Done()
		n := spliceOneDir(client, upstream, lastActivity)
		upBytes.Add(n)
		// Half-close: signal upstream that client is done.
		if tc, ok := upstream.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// upstream → client (download)
	go func() {
		defer wg.Done()
		n := spliceOneDir(upstream, client, lastActivity)
		downBytes.Add(n)
		// Half-close: signal client that upstream is done.
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

// spliceOneDir moves data from src to dst using splice(2) if possible,
// falling back to io.CopyBuffer otherwise. Returns total bytes transferred.
func spliceOneDir(src, dst net.Conn, lastActivity *atomic.Int64) int64 {
	srcFD, srcErr := connFD(src)
	dstFD, dstErr := connFD(dst)
	if srcErr != nil || dstErr != nil {
		return fallbackCopyOneDir(src, dst, lastActivity)
	}

	pipe := getPipe()
	if pipe == nil {
		return fallbackCopyOneDir(src, dst, lastActivity)
	}
	defer putPipe(pipe)

	var total int64
	for {
		// splice: src socket → pipe write end
		n, err := spliceFD(srcFD, pipe.w, spliceChunkSize)
		if n > 0 {
			// splice: pipe read end → dst socket
			// Must drain the pipe completely.
			written := 0
			for written < int(n) {
				w, werr := spliceFD(pipe.r, dstFD, int(n)-written)
				if w > 0 {
					written += int(w)
					total += int64(w)
				}
				if werr != nil {
					// Pipe→dst failed; discard remaining pipe data.
					closePipe(pipe)
					// Keep source and destination alive until splice is done.
					runtime.KeepAlive(src)
					runtime.KeepAlive(dst)
					return total
				}
			}
			// Reset idle timer after successful data transfer.
			if lastActivity != nil {
				lastActivity.Store(time.Now().UnixNano())
			}
		}
		if err != nil {
			// Keep source and destination alive until splice is done.
			runtime.KeepAlive(src)
			runtime.KeepAlive(dst)
			return total
		}
	}
}

// spliceFD wraps the splice(2) syscall, retrying on EINTR and handling EAGAIN
// by returning 0 bytes with nil error (caller should use poll/retry).
func spliceFD(srcFD, dstFD int, max int) (int, error) {
	for {
		n, err := unix.Splice(srcFD, nil, dstFD, nil, max, int(spliceFlagMore))
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			// Non-blocking fd is not ready; treat as EOF for the splice loop.
			// The Go runtime will re-poll when the underlying goroutine is rescheduled.
			return 0, nil
		}
		if n == 0 || err != nil {
			if err == nil {
				err = io.EOF
			}
			return int(n), err
		}
		return int(n), nil
	}
}

// connFD extracts the raw file descriptor from a net.Conn via syscall.Conn.
// The fd is valid only for immediate syscall use within the same goroutine.
func connFD(c net.Conn) (int, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, errors.New("conn does not implement syscall.Conn")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}

	var fd int
	err = rc.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return 0, err
	}
	return fd, nil
}

// fallbackCopyOneDir copies from src to dst using io.CopyBuffer with a pooled
// 16KB buffer. Used when splice(2) is not available.
func fallbackCopyOneDir(src, dst net.Conn, lastActivity *atomic.Int64) int64 {
	buf := pool.GetRelayBuf()
	defer pool.PutRelayBuf(buf)
	n, _ := io.CopyBuffer(&activityWriter{conn: dst, lastActivity: lastActivity}, src, *buf)
	return n
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
