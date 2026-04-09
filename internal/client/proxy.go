package client

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"prism/internal/ech"
	"prism/pkg/pool"
	"prism/pkg/stream"
)

// Proxy is a local TLS proxy that intercepts plaintext ClientHello connections,
// wraps them in ECH, and forwards to the remote Prism Gateway.
//
// It listens on a local address (e.g. 127.0.0.1:10443). Local applications
// connect to it thinking it's the real server (because LocalDNS resolved
// everything to 127.0.0.1). Proxy reads the ClientHello, extracts the SNI,
// re-encrypts it using ECH, and forwards the connection to the gateway.
type Proxy struct {
	Addr      string         // Listen address (e.g. "127.0.0.1:10443")
	Gateway   string         // Remote gateway address (e.g. "prism.example.com:443")
	Encryptor *ech.Encryptor // ECH encryptor initialised with the gateway's ECHConfig

	listener net.Listener
}

// NewProxy creates a new Proxy instance.
func NewProxy(addr, gateway string, encryptor *ech.Encryptor) *Proxy {
	return &Proxy{
		Addr:      addr,
		Gateway:   gateway,
		Encryptor: encryptor,
	}
}

// Serve starts the proxy and blocks until ctx is cancelled.
func (p *Proxy) Serve(ctx context.Context) error {
	var err error
	p.listener, err = net.Listen("tcp", p.Addr)
	if err != nil {
		return err
	}

	slog.Info("proxy_started", "addr", p.Addr, "gateway", p.Gateway)

	// Close listener when context is cancelled.
	go func() {
		<-ctx.Done()
		p.listener.Close()
	}()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Error("proxy_accept_failed", "err", err)
			continue
		}
		go p.handleConn(conn)
	}
}

// handleConn processes a single incoming connection.
func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	// Set deadline for reading the ClientHello.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read the first TLS record (ClientHello).
	rr := stream.NewRecordReader(conn)
	record, err := rr.ReadRecord()
	if err != nil {
		slog.Debug("proxy_read_ch_failed", "err", err, "remote", conn.RemoteAddr())
		return
	}

	// Parse the plaintext ClientHello to extract SNI.
	parsed, err := ech.Parse(record)
	if err != nil {
		slog.Debug("proxy_parse_ch_failed", "err", err)
		return
	}

	sni := parsed.OuterSNI
	if sni == "" {
		slog.Debug("proxy_no_sni", "remote", conn.RemoteAddr())
		return
	}

	// Clear deadline for the relay phase.
	conn.SetReadDeadline(time.Time{})

	slog.Debug("proxy_intercepted", "sni", sni, "remote", conn.RemoteAddr())

	// Re-encrypt the ClientHello with ECH.
	outerRecord, err := p.Encryptor.Encrypt(record)
	if err != nil {
		slog.Error("proxy_ech_encrypt_failed", "sni", sni, "err", err)
		return
	}

	// Dial the remote gateway.
	gwConn, err := net.DialTimeout("tcp", p.Gateway, 5*time.Second)
	if err != nil {
		slog.Error("proxy_dial_gw_failed", "gateway", p.Gateway, "err", err)
		return
	}
	defer gwConn.Close()

	// Send the ECH-wrapped ClientHello to the gateway.
	if _, err := gwConn.Write(outerRecord); err != nil {
		slog.Error("proxy_write_gw_failed", "err", err)
		return
	}

	// Bidirectional relay.
	relay(conn, gwConn)
}

// relay performs bidirectional copy between two connections using pooled buffers.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst, src net.Conn) {
		defer wg.Done()
		buf := pool.GetRelayBuf()
		defer pool.PutRelayBuf(buf)
		io.CopyBuffer(dst, src, *buf)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copyDir(b, a) // client → gateway
	go copyDir(a, b) // gateway → client

	wg.Wait()
}

// Close shuts down the proxy listener.
func (p *Proxy) Close() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}
