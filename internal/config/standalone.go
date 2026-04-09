// Package config provides runtime configuration for the Prism gateway.
// standalone.go implements the SNI-dispatch server for standalone mode,
// where DoH and Gateway share a single :443 listener.
package config

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"prism/internal/ech"
	"prism/internal/gateway"
	"prism/pkg/connutil"
	"prism/pkg/stream"
)

// StandaloneServer multiplexes a single :443 TCP listener between
// the DoH handler (SNI == BaseDomain) and the Gateway (everything else).
type StandaloneServer struct {
	// Listener is the shared raw TCP listener (typically :443).
	Listener net.Listener

	// DNSHandler serves DoH requests for connections matching BaseDomain.
	DNSHandler http.Handler

	// Gateway handles ECH/camouflage connections (all other SNIs).
	Gateway *gateway.Server

	// BaseDomain is the DNS domain (e.g., "prism.example.com").
	// Connections whose SNI matches this exactly are routed to DoH.
	BaseDomain string

	// TLSConfig is used for the DoH TLS handshake.
	TLSConfig *tls.Config
}

// Serve accepts connections and dispatches them by SNI.
// It blocks until ctx is cancelled or the listener is closed.
func (s *StandaloneServer) Serve(ctx context.Context) error {
	// Close listener on context cancellation.
	go func() {
		<-ctx.Done()
		s.Listener.Close()
	}()

	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("standalone: accept: %w", err)
		}
		go s.dispatch(conn)
	}
}

// dispatch reads the first TLS record, extracts the SNI, and routes.
func (s *StandaloneServer) dispatch(conn net.Conn) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	rr := stream.NewRecordReader(conn)
	record, err := rr.ReadRecord()
	if err != nil {
		slog.Debug("standalone_read_failed", "err", err, "remote", conn.RemoteAddr())
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	// Try to parse the ClientHello to extract SNI.
	parsed, err := ech.Parse(record)
	if err != nil {
		// Not a valid ClientHello — send to gateway (which will handle non-TLS).
		pc := connutil.NewPrefixConn(conn, record)
		s.Gateway.HandleConn(pc)
		return
	}

	sni := parsed.OuterSNI

	if sni == s.BaseDomain {
		// Route to DoH handler via TLS + HTTP.
		s.serveDoH(conn, record)
		return
	}

	// Everything else goes to the gateway.
	pc := connutil.NewPrefixConn(conn, record)
	s.Gateway.HandleConn(pc)
}

// serveDoH wraps the connection in TLS and serves a single HTTP request
// through the DoH handler.
func (s *StandaloneServer) serveDoH(conn net.Conn, record []byte) {
	pc := connutil.NewPrefixConn(conn, record)
	tlsConn := tls.Server(pc, s.TLSConfig)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("standalone_doh_tls_failed", "err", err, "remote", conn.RemoteAddr())
		tlsConn.Close()
		return
	}
	tlsConn.SetDeadline(time.Now().Add(30 * time.Second))

	srv := &http.Server{
		Handler:      s.DNSHandler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Serve exactly one HTTP connection.
	ln := &singleConnListener{conn: tlsConn}
	srv.Serve(ln)
}

// singleConnListener yields exactly one connection, then returns ErrClosed.
type singleConnListener struct {
	conn net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
