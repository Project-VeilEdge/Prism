package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"prism/internal/ech"
	"prism/internal/relay"
)

// MITMProxy handles intercepted TLS connections for whitelisted domains.
type MITMProxy interface {
	Handle(ctx context.Context, clientConn net.Conn, innerSNI string, m *ConnMetrics) error
}

// MITMUpstream dials origin servers over TLS.
type MITMUpstream interface {
	DialTLS(ctx context.Context, serverName string) (*tls.Conn, error)
}

type routeAwareMITMUpstream interface {
	DialTLSWithRoute(ctx context.Context, serverName string) (*tls.Conn, string, error)
}

// DirectMITMProxy terminates the browser TLS session with a dynamically issued
// leaf certificate and bridges application bytes to/from the real origin.
type DirectMITMProxy struct {
	KeySource ECHKeySource
	Users     UserMatcher
	Whitelist WhitelistChecker
	Issuer    *MITMIssuer
	Upstream  MITMUpstream
}

// Handle performs MITM interception:
//  1. Issues a leaf cert for innerSNI
//  2. Dials upstream TLS to the origin
//  3. Completes TLS handshake with the browser using the leaf cert
//  4. Relays application bytes bidirectionally
func (p *DirectMITMProxy) Handle(ctx context.Context, clientConn net.Conn, outerOrInnerSNI string, m *ConnMetrics) error {
	if p == nil || p.Issuer == nil {
		err := errors.New("mitm issuer not configured")
		m.ErrorType = classifyMITMError(err)
		slog.Debug("mitm_error", "sni", outerOrInnerSNI, "phase", m.ErrorType, "err", err)
		return err
	}

	if p.shouldUseNativeECH(outerOrInnerSNI) {
		return p.handleNativeECH(ctx, clientConn, outerOrInnerSNI, m)
	}

	return p.handlePlainTLS(ctx, clientConn, outerOrInnerSNI, m)
}

func (p *DirectMITMProxy) handlePlainTLS(ctx context.Context, clientConn net.Conn, innerSNI string, m *ConnMetrics) error {
	leaf, err := p.Issuer.CertificateFor(innerSNI)
	if err != nil {
		err = fmt.Errorf("issue leaf: %w", err)
		m.ErrorType = classifyMITMError(err)
		slog.Debug("mitm_error", "sni", innerSNI, "phase", m.ErrorType, "err", err)
		return err
	}

	upstream, route, err := p.dialUpstream(ctx, innerSNI)
	if err != nil {
		err = fmt.Errorf("upstream dial: %w", err)
		m.ErrorType = classifyMITMError(err)
		slog.Debug("mitm_error", "sni", innerSNI, "phase", m.ErrorType, "err", err)
		return err
	}
	defer upstream.Close()
	m.Egress = route

	browserTLS := tls.Server(clientConn, newMITMBrowserTLSConfig(
		0,
		[]tls.Certificate{*leaf},
		nil,
		nil,
	))
	if err := browserTLS.HandshakeContext(ctx); err != nil {
		err = fmt.Errorf("browser handshake: %w", err)
		m.ErrorType = classifyMITMError(err)
		slog.Debug("mitm_error", "sni", innerSNI, "phase", m.ErrorType, "err", err)
		return err
	}
	defer browserTLS.Close()

	m.InnerSNI = innerSNI
	upWriter, downWriter := relay.NewRelayPair(browserTLS, upstream)
	relay.RelayWithMetrics(browserTLS, upstream, upWriter, downWriter)
	m.UpBytes = upWriter.Bytes()
	m.DownBytes = downWriter.Bytes()
	if m.UpBytes+m.DownBytes == 0 {
		slog.Debug("mitm_zero_bytes", "sni", innerSNI)
	}
	return nil
}

func (p *DirectMITMProxy) handleNativeECH(ctx context.Context, clientConn net.Conn, outerSNI string, m *ConnMetrics) error {
	browserTLS, upstream, innerSNI, userHash, route, err := p.handshakeBrowserECH(ctx, clientConn, outerSNI)
	if err != nil {
		m.ErrorType = classifyMITMError(err)
		slog.Debug("mitm_error", "sni", outerSNI, "phase", m.ErrorType, "err", err)
		return err
	}
	defer browserTLS.Close()
	defer upstream.Close()

	browserState := browserTLS.ConnectionState()
	m.UserHash = userHash
	if p.Users != nil {
		m.UserID = p.Users.LookupUserID(userHash)
	}
	m.InnerSNI = innerSNI
	m.Egress = route
	m.ECHSuccess = browserState.ECHAccepted
	slog.Info("mitm_browser_ech_ok",
		"outer_sni", outerSNI,
		"inner_sni", innerSNI,
		"ech_accepted", browserState.ECHAccepted,
		"alpn", browserState.NegotiatedProtocol,
	)

	upWriter, downWriter := relay.NewRelayPair(browserTLS, upstream)
	relay.RelayWithMetrics(browserTLS, upstream, upWriter, downWriter)
	m.UpBytes = upWriter.Bytes()
	m.DownBytes = downWriter.Bytes()
	if m.UpBytes+m.DownBytes == 0 {
		slog.Debug("mitm_zero_bytes", "sni", innerSNI)
	}
	return nil
}

func (p *DirectMITMProxy) handshakeBrowserECH(ctx context.Context, clientConn net.Conn, expectedOuterSNI string) (*tls.Conn, *tls.Conn, string, string, string, error) {
	var (
		innerSNI          string
		userHash          string
		route             string
		callErr           error
		validatedOuterSNI string
		upstream          *tls.Conn
	)
	closeUpstream := func() {
		if upstream != nil {
			upstream.Close()
			upstream = nil
		}
	}

	browserTLS := tls.Server(clientConn, newMITMBrowserTLSConfig(
		tls.VersionTLS13,
		nil,
		func(chi *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			keySet := p.KeySource.KeySet()
			if keySet == nil {
				callErr = errors.New("ech keyset missing")
				return nil, callErr
			}

			if validatedOuterSNI == "" {
				if expectedOuterSNI != "" && chi.ServerName != expectedOuterSNI {
					callErr = fmt.Errorf("outer sni mismatch: got %q, want %q", chi.ServerName, expectedOuterSNI)
					return nil, callErr
				}

				userHash = extractNativeECHUserHash(chi.ServerName, keySet)
				if userHash == "" || !p.Users.IsValidUser(userHash) {
					callErr = fmt.Errorf("user invalid: %s", chi.ServerName)
					return nil, callErr
				}
				validatedOuterSNI = chi.ServerName
			}

			keys, err := buildECHKeysForOuterSNI(keySet, validatedOuterSNI)
			if err != nil {
				callErr = fmt.Errorf("native ech keys: %w", err)
				return nil, callErr
			}
			return keys, nil
		},
		func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if userHash == "" {
				callErr = errors.New("user invalid")
				return nil, callErr
			}
			if chi.ServerName == "" {
				callErr = errors.New("inner sni missing")
				return nil, callErr
			}
			if validatedOuterSNI != "" && chi.ServerName == validatedOuterSNI {
				leaf, err := p.Issuer.CertificateFor(validatedOuterSNI)
				if err != nil {
					callErr = fmt.Errorf("issue leaf: %w", err)
					return nil, callErr
				}
				return leaf, nil
			}
			if !p.Whitelist.Contains(chi.ServerName) {
				callErr = fmt.Errorf("not whitelisted: %s", chi.ServerName)
				return nil, callErr
			}

			innerSNI = chi.ServerName
			if upstream == nil {
				var err error
				upstream, route, err = p.dialUpstream(ctx, chi.ServerName)
				if err != nil {
					callErr = fmt.Errorf("upstream dial: %w", err)
					return nil, callErr
				}
			}
			leaf, err := p.Issuer.CertificateFor(chi.ServerName)
			if err != nil {
				callErr = fmt.Errorf("issue leaf: %w", err)
				return nil, callErr
			}
			return leaf, nil
		},
	))

	if err := browserTLS.HandshakeContext(ctx); err != nil {
		closeUpstream()
		if callErr != nil {
			return nil, nil, "", "", "", callErr
		}
		return nil, nil, "", "", "", fmt.Errorf("browser handshake: %w", err)
	}
	if !browserTLS.ConnectionState().ECHAccepted {
		closeUpstream()
		browserTLS.Close()
		return nil, nil, "", "", "", fmt.Errorf("ech not accepted for %s", validatedOuterSNI)
	}
	if innerSNI == "" {
		innerSNI = browserTLS.ConnectionState().ServerName
	}
	if innerSNI == "" {
		closeUpstream()
		browserTLS.Close()
		return nil, nil, "", "", "", errors.New("inner sni missing")
	}
	if upstream == nil {
		browserTLS.Close()
		return nil, nil, "", "", "", errors.New("upstream missing")
	}
	return browserTLS, upstream, innerSNI, userHash, route, nil
}

func (p *DirectMITMProxy) dialUpstream(ctx context.Context, serverName string) (*tls.Conn, string, error) {
	if routed, ok := p.Upstream.(routeAwareMITMUpstream); ok {
		return routed.DialTLSWithRoute(ctx, serverName)
	}
	upstream, err := p.Upstream.DialTLS(ctx, serverName)
	if err != nil {
		return nil, "", err
	}
	return upstream, "direct", nil
}

func (p *DirectMITMProxy) shouldUseNativeECH(serverName string) bool {
	if p == nil || p.KeySource == nil || p.Users == nil || p.Whitelist == nil {
		return false
	}
	return extractNativeECHUserHash(serverName, p.KeySource.KeySet()) != ""
}

func extractNativeECHUserHash(serverName string, ks *ech.KeySet) string {
	for _, suffix := range nativeECHOuterSuffixes(ks) {
		hash, ok := extractHashForNativeECHSuffix(serverName, suffix)
		if ok {
			return hash
		}
	}
	return ""
}

func nativeECHOuterSuffixes(ks *ech.KeySet) []string {
	if ks == nil {
		return nil
	}

	seen := make(map[string]struct{}, 2)
	var suffixes []string
	for _, pair := range []*ech.KeyPair{ks.Current, ks.Previous} {
		suffix, ok := nativeECHOuterSuffix(pair)
		if !ok {
			continue
		}
		if _, dup := seen[suffix]; dup {
			continue
		}
		seen[suffix] = struct{}{}
		suffixes = append(suffixes, suffix)
	}
	return suffixes
}

func nativeECHOuterSuffix(pair *ech.KeyPair) (string, bool) {
	if pair == nil || len(pair.Config) == 0 {
		return "", false
	}

	enc, err := ech.NewEncryptor(pair.Config)
	if err != nil {
		return "", false
	}
	publicName := enc.PublicName()
	if publicName == "" {
		return "", false
	}

	hash, rest, ok := strings.Cut(publicName, ".")
	if ok && isValidHash(hash) && rest != "" {
		return rest, true
	}
	return publicName, true
}

func extractHashForNativeECHSuffix(serverName, suffix string) (string, bool) {
	if serverName == "" || suffix == "" {
		return "", false
	}

	wantSuffix := "." + suffix
	if !strings.HasSuffix(serverName, wantSuffix) {
		return "", false
	}

	hash := strings.TrimSuffix(serverName, wantSuffix)
	if strings.Contains(hash, ".") || !isValidHash(hash) {
		return "", false
	}
	return hash, true
}

func classifyMITMError(err error) string {
	if err == nil {
		return "unknown"
	}
	msg := err.Error()

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) || strings.Contains(msg, "no upstream IPs") || strings.Contains(msg, "resolve") {
		return "dns_resolve"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && strings.Contains(msg, "connection refused") {
		return "dial_refused"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "dial_timeout"
	}

	if strings.Contains(msg, "browser handshake") {
		return "browser_tls"
	}

	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) || strings.Contains(msg, "upstream handshake") || strings.Contains(msg, "tls:") {
		return "upstream_tls"
	}

	if strings.Contains(msg, "issue leaf") {
		return "cert_issue"
	}

	if strings.Contains(msg, "relay") || errors.Is(err, io.EOF) {
		return "relay"
	}

	return "unknown"
}
