package gateway

import "crypto/tls"

// The browser-facing MITM TLS path shares common defaults for ALPN, TLS minimum
// version, and dynamic certificate/ECH callbacks. Curve negotiation is left to
// Go's crypto/tls defaults: explicit CurvePreferences caused broad compatibility
// regressions on the MITM paths and are intentionally omitted here.
func newMITMBrowserTLSConfig(
	minVersion uint16,
	certs []tls.Certificate,
	getECHKeys func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error),
	getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error),
) *tls.Config {
	cfg := &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	if minVersion != 0 {
		cfg.MinVersion = minVersion
	}
	if len(certs) > 0 {
		cfg.Certificates = certs
	}
	if getECHKeys != nil {
		cfg.GetEncryptedClientHelloKeys = getECHKeys
	}
	if getCert != nil {
		cfg.GetCertificate = getCert
	}
	return cfg
}
