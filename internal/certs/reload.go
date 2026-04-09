package certs

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// CertReloader provides hot-reloadable TLS certificates via the
// tls.Config.GetCertificate callback. It stores the current certificate
// in an atomic.Pointer, allowing lock-free reads during TLS handshakes.
type CertReloader struct {
	certFile string
	keyFile  string
	cert     atomic.Pointer[tls.Certificate]
}

// NewCertReloader loads a TLS certificate from certFile and keyFile,
// returning a CertReloader that can be used with tls.Config.GetCertificate.
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	cr := &CertReloader{
		certFile: certFile,
		keyFile:  keyFile,
	}
	if err := cr.Reload(); err != nil {
		return nil, fmt.Errorf("initial load: %w", err)
	}
	return cr, nil
}

// Reload re-reads the certificate and key files from disk and swaps
// the in-memory certificate atomically. On failure, the old certificate
// remains active.
func (cr *CertReloader) Reload() error {
	cert, err := tls.LoadX509KeyPair(cr.certFile, cr.keyFile)
	if err != nil {
		return fmt.Errorf("load cert %q / key %q: %w", cr.certFile, cr.keyFile, err)
	}
	cr.cert.Store(&cert)
	slog.Info("tls_cert_reloaded", "cert", cr.certFile)
	return nil
}

// GetCertificate returns a function suitable for tls.Config.GetCertificate.
// It reads the certificate from the atomic pointer — no locks, no I/O.
func (cr *CertReloader) GetCertificate() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c := cr.cert.Load()
		if c == nil {
			return nil, fmt.Errorf("no TLS certificate loaded")
		}
		return c, nil
	}
}

// Current returns the currently loaded certificate (may be nil before first load).
func (cr *CertReloader) Current() *tls.Certificate {
	return cr.cert.Load()
}

// TLSConfig returns a tls.Config that uses GetCertificate for dynamic cert loading.
func (cr *CertReloader) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: cr.GetCertificate(),
	}
}

// WatchMtime polls the cert and key files for mtime changes at the given
// interval. When a change is detected, it calls Reload(). The goroutine
// stops when ctx is cancelled.
func (cr *CertReloader) WatchMtime(ctx context.Context, interval time.Duration) {
	certMtime := fileMtime(cr.certFile)
	keyMtime := fileMtime(cr.keyFile)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newCertMtime := fileMtime(cr.certFile)
			newKeyMtime := fileMtime(cr.keyFile)

			if newCertMtime != certMtime || newKeyMtime != keyMtime {
				slog.Info("tls_cert_changed", "cert", cr.certFile, "key", cr.keyFile)
				if err := cr.Reload(); err != nil {
					slog.Error("tls_cert_reload_failed", "err", err)
					continue
				}
				certMtime = newCertMtime
				keyMtime = newKeyMtime
			}
		}
	}
}

// fileMtime returns the mtime of a file, or zero time on error.
func fileMtime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}
