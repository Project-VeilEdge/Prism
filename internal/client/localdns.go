// Package client implements the prism-client local proxy for non-ECH devices.
// It intercepts local DNS and TLS traffic, wrapping outbound connections in ECH.
package client

import (
	"context"
	"log/slog"
	"net"

	"github.com/miekg/dns"
)

// LocalDNS is a minimal DNS server that listens on a local address (e.g. 127.0.0.1:10053)
// and resolves all A/AAAA queries to 127.0.0.1 / ::1.
// This hijacks DNS resolution so that all traffic destined for whitelisted domains
// is redirected to the local TLS proxy (which then wraps it in ECH).
type LocalDNS struct {
	Addr   string // Listen address (e.g. "127.0.0.1:10053")
	server *dns.Server
}

// NewLocalDNS creates a LocalDNS instance on the given address.
func NewLocalDNS(addr string) *LocalDNS {
	return &LocalDNS{Addr: addr}
}

// Serve starts the DNS server and blocks until ctx is cancelled or an error occurs.
func (ld *LocalDNS) Serve(ctx context.Context) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", ld.handleQuery)

	ld.server = &dns.Server{
		Addr:    ld.Addr,
		Net:     "udp",
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- ld.server.ListenAndServe()
	}()

	slog.Info("localdns_started", "addr", ld.Addr)

	select {
	case <-ctx.Done():
		ld.server.Shutdown()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// handleQuery responds to DNS queries by returning 127.0.0.1 for A records
// and ::1 for AAAA records. All other query types get an empty response.
func (ld *LocalDNS) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("127.0.0.1"),
			})
			slog.Debug("localdns_a", "name", q.Name)

		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				AAAA: net.ParseIP("::1"),
			})
			slog.Debug("localdns_aaaa", "name", q.Name)
		}
	}

	if err := w.WriteMsg(m); err != nil {
		slog.Error("localdns_write_failed", "err", err)
	}
}

// Close shuts down the DNS server.
func (ld *LocalDNS) Close() error {
	if ld.server != nil {
		return ld.server.Shutdown()
	}
	return nil
}
