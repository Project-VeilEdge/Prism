// Package connutil provides connection-level utilities for the Prism gateway.
package connutil

import (
	"io"
	"net"
	"time"
)

// PrefixConn wraps a net.Conn, prepending already-read bytes (the "prefix")
// back in front of the connection's read stream. This allows bytes consumed
// during classification (e.g., TLS ClientHello) to be "unread" so that
// subsequent readers (e.g., tls.Server) see the full original byte stream.
//
// All net.Conn methods are fully proxied to the underlying connection.
type PrefixConn struct {
	conn   net.Conn
	reader io.Reader // MultiReader(prefix, conn)
}

// NewPrefixConn creates a PrefixConn that yields prefix bytes first,
// then transparently reads from the underlying conn.
func NewPrefixConn(conn net.Conn, prefix []byte) *PrefixConn {
	return &PrefixConn{
		conn:   conn,
		reader: io.MultiReader(io.LimitReader(newBytesReader(prefix), int64(len(prefix))), conn),
	}
}

// Read returns prefix bytes first, then reads from the underlying connection.
func (pc *PrefixConn) Read(b []byte) (int, error) {
	return pc.reader.Read(b)
}

// Write proxies to the underlying connection.
func (pc *PrefixConn) Write(b []byte) (int, error) {
	return pc.conn.Write(b)
}

// Close proxies to the underlying connection.
func (pc *PrefixConn) Close() error {
	return pc.conn.Close()
}

// LocalAddr proxies to the underlying connection.
func (pc *PrefixConn) LocalAddr() net.Addr {
	return pc.conn.LocalAddr()
}

// RemoteAddr proxies to the underlying connection.
func (pc *PrefixConn) RemoteAddr() net.Addr {
	return pc.conn.RemoteAddr()
}

// SetDeadline proxies to the underlying connection.
func (pc *PrefixConn) SetDeadline(t time.Time) error {
	return pc.conn.SetDeadline(t)
}

// SetReadDeadline proxies to the underlying connection.
func (pc *PrefixConn) SetReadDeadline(t time.Time) error {
	return pc.conn.SetReadDeadline(t)
}

// SetWriteDeadline proxies to the underlying connection.
func (pc *PrefixConn) SetWriteDeadline(t time.Time) error {
	return pc.conn.SetWriteDeadline(t)
}

// Compile-time check that PrefixConn implements net.Conn.
var _ net.Conn = (*PrefixConn)(nil)

// bytesReader is a minimal io.Reader over a byte slice, used to avoid
// importing bytes just for bytes.NewReader.
type bytesReader struct {
	data []byte
	off  int
}

func newBytesReader(data []byte) *bytesReader {
	cp := make([]byte, len(data))
	copy(cp, data)
	return &bytesReader{data: cp}
}

func (r *bytesReader) Read(b []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(b, r.data[r.off:])
	r.off += n
	return n, nil
}
