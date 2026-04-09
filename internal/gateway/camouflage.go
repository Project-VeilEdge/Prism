package gateway

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"time"

	"prism/pkg/connutil"
)

const (
	// camouflageHandshakeTimeout is the TLS handshake timeout for camouflage connections.
	camouflageHandshakeTimeout = 10 * time.Second
	// camouflageSessionTimeout is the total HTTP session timeout for camouflage.
	camouflageSessionTimeout = 30 * time.Second
	// camouflageMaxRequests is the maximum number of HTTP requests served on a camouflage connection.
	camouflageMaxRequests = 3
)

// Camouflage handles non-ECH TLS connections by completing a standard TLS
// handshake using the gateway's camouflage certificate and serving HTTP
// requests through the provided handler.
//
// It wraps the raw TCP connection in a prefixConn (to replay already-read
// bytes from classification), then performs a TLS handshake with the
// gateway's certificate, and finally serves up to camouflageMaxRequests
// HTTP requests with a total session timeout.
type Camouflage struct {
	TLSConfig *tls.Config
	Handler   http.Handler
}

// Serve handles a camouflage connection. record is the already-read TLS record
// from the classification phase that must be replayed.
func (c *Camouflage) Serve(rawConn net.Conn, record []byte) {
	// Wrap with prefixConn to replay the already-read record bytes.
	pc := connutil.NewPrefixConn(rawConn, record)

	// TLS handshake with deadline.
	tlsConn := tls.Server(pc, c.TLSConfig)
	tlsConn.SetDeadline(time.Now().Add(camouflageHandshakeTimeout))

	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("camouflage_handshake_failed", "err", err, "remote", rawConn.RemoteAddr())
		tlsConn.Close()
		return
	}

	// Set session-level deadline for HTTP serving.
	tlsConn.SetDeadline(time.Now().Add(camouflageSessionTimeout))

	// Serve limited HTTP requests.
	serveCamouflageHTTP(tlsConn, c.Handler)
}

// serveCamouflageHTTP reads and serves up to camouflageMaxRequests HTTP requests
// on the given TLS connection. The connection is closed when done.
func serveCamouflageHTTP(conn net.Conn, handler http.Handler) {
	defer conn.Close()

	// Use a single-connection HTTP server with request limit.
	srv := &http.Server{
		Handler:     handler,
		ReadTimeout: camouflageSessionTimeout,
		IdleTimeout: camouflageSessionTimeout,
	}

	// Create a one-shot listener that yields this single connection.
	ln := &singleConnListener{conn: conn}
	srv.Serve(ln)
}

// singleConnListener is a net.Listener that yields exactly one connection,
// then returns an error to stop the server. It also enforces a maximum
// request count via the wrapped limitConn.
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return &limitConn{Conn: l.conn}, nil
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

// limitConn wraps a connection for the single-connection HTTP server.
// The session timeout and Keep-Alive mechanism handle connection teardown.
type limitConn struct {
	net.Conn
}
