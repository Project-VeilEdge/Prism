package quic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"prism/internal/ech"
	"prism/internal/egress"
)

const (
	// MaxDatagramSize is the maximum UDP datagram size we accept.
	// QUIC mandates at least 1200 bytes for Initial packets; typical MTU is 1500.
	MaxDatagramSize = 1500

	// IdleTimeout is the duration after which a UDP session with no traffic
	// is considered dead and its resources are reclaimed.
	IdleTimeout = 5 * time.Minute

	// SessionReapInterval is how often the reaper goroutine scans for idle sessions.
	SessionReapInterval = 30 * time.Second

	// DefaultMaxSessions is the maximum number of concurrent UDP sessions.
	// Once reached, new sessions are silently dropped to prevent memory exhaustion
	// from UDP floods with spoofed source addresses.
	DefaultMaxSessions = 100_000

	sessionSetupTimeout = 5 * time.Second
)

// FiveTuple uniquely identifies a UDP "session" (since UDP is connectionless).
type FiveTuple struct {
	SrcIP   [16]byte // source IP as 16-byte (v4-mapped-v6)
	DstIP   [16]byte // destination IP as 16-byte
	SrcPort uint16
	DstPort uint16
}

// MakeFiveTuple constructs a FiveTuple from source and destination UDP addresses.
func MakeFiveTuple(src, dst *net.UDPAddr) FiveTuple {
	var ft FiveTuple
	copy(ft.SrcIP[:], src.IP.To16())
	copy(ft.DstIP[:], dst.IP.To16())
	ft.SrcPort = uint16(src.Port)
	ft.DstPort = uint16(dst.Port)
	return ft
}

// Session tracks a single UDP "connection" between client and upstream.
type Session struct {
	mu          sync.Mutex
	cleanupOnce sync.Once
	Key         FiveTuple
	ClientAddr  *net.UDPAddr // original client address
	Upstream    DatagramSession
	LastActive  time.Time
	BytesUp     int64
	BytesDown   int64
	InnerSNI    string
	UserID      string
	Closed      bool
}

// Touch updates the last activity timestamp.
func (s *Session) Touch() {
	s.mu.Lock()
	s.LastActive = time.Now()
	s.mu.Unlock()
}

// Close shuts down the session's upstream connection.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Closed {
		return
	}
	s.Closed = true
	if s.Upstream != nil {
		_ = s.Upstream.Close()
	}
}

// ECHDecryptor abstracts the ECH key set for decryption.
type ECHDecryptor interface {
	DecryptWithPublicName(result *ech.ParseResult, publicName string) (innerSNI string, innerCHRecord []byte, err error)
}

// ECHKeySource provides the current ECH key set.
type ECHKeySource interface {
	KeySet() *ech.KeySet
}

// UserMatcher abstracts user lookup by hash from outer SNI.
type UserMatcher interface {
	IsValidUser(hash string) bool
	LookupUserID(hash string) string
}

// WhitelistChecker abstracts domain whitelist checking.
type WhitelistChecker interface {
	Contains(domain string) bool
}

// Resolver resolves a domain to IP addresses.
type Resolver interface {
	Resolve(ctx context.Context, domain string) ([]net.IP, error)
}

// RouteSelector selects egress nodes in priority order.
type RouteSelector interface {
	RouteAll(domain string, targetIP net.IP) []*egress.EgressNode
}

// DatagramSession represents a UDP session to an upstream target.
type DatagramSession = egress.DatagramSession

// DatagramSessionFactory opens outbound UDP sessions.
type DatagramSessionFactory interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

// DatagramEgressClient forwards datagrams through a remote egress node.
type DatagramEgressClient interface {
	OpenSession(ctx context.Context, node *egress.EgressNode, targetIP net.IP, targetPort uint16, firstDatagram []byte) (egress.DatagramSession, error)
}

type netPacketFactory struct{}

func (netPacketFactory) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, address)
}

type directDatagramSession struct {
	conn      net.PacketConn
	target    net.Addr
	closeOnce sync.Once
}

func newDirectDatagramSession(conn net.PacketConn, target net.Addr) DatagramSession {
	return &directDatagramSession{conn: conn, target: target}
}

func (s *directDatagramSession) Write(datagram []byte) error {
	_, err := s.conn.WriteTo(datagram, s.target)
	return err
}

func (s *directDatagramSession) Read(ctx context.Context) ([]byte, error) {
	buf := make([]byte, MaxDatagramSize)
	for {
		deadline, hasDeadline := ctx.Deadline()
		if !hasDeadline {
			deadline = time.Now().Add(250 * time.Millisecond)
		}
		if err := s.conn.SetReadDeadline(deadline); err != nil {
			return nil, err
		}

		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if !hasDeadline {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					continue
				}
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		if !sameDatagramAddr(s.target, addr) {
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])
		return payload, nil
	}
}

func (s *directDatagramSession) Close() error {
	var err error
	s.closeOnce.Do(func() {
		err = s.conn.Close()
	})
	return err
}

func sameDatagramAddr(expected, actual net.Addr) bool {
	if expected == nil || actual == nil {
		return false
	}

	expectedUDP, expectedOK := expected.(*net.UDPAddr)
	actualUDP, actualOK := actual.(*net.UDPAddr)
	if expectedOK && actualOK {
		return expectedUDP.IP.Equal(actualUDP.IP) &&
			expectedUDP.Port == actualUDP.Port &&
			expectedUDP.Zone == actualUDP.Zone
	}

	return expected.Network() == actual.Network() && expected.String() == actual.String()
}

// Handler is the UDP Gateway that intercepts QUIC traffic,
// parses Initial packets for ECH, and forwards datagrams.
type Handler struct {
	// ListenConn is the UDP socket receiving inbound traffic (typically port 443).
	ListenConn net.PacketConn

	// ECH decryption.
	KeySet ECHDecryptor

	// KeySource allows the handler to use the current ECH key set.
	KeySource ECHKeySource

	// User validation.
	Users      UserMatcher
	Whitelist  WhitelistChecker
	BaseDomain string

	// Target resolution and routing.
	Resolver       Resolver
	Router         RouteSelector
	EgressClient   DatagramEgressClient
	SessionFactory DatagramSessionFactory

	// MaxSessions is the maximum number of concurrent sessions.
	// Zero means DefaultMaxSessions.
	MaxSessions int64

	// sessions maps FiveTuple → *Session for active UDP flows.
	sessions sync.Map // map[FiveTuple]*Session

	// sessionCount tracks the number of active sessions for capacity enforcement.
	sessionCount atomic.Int64

	// DroppedSessions counts sessions dropped due to capacity limits (for metrics).
	DroppedSessions atomic.Int64

	// done signals the handler to stop.
	done     chan struct{}
	doneOnce sync.Once
}

// NewHandler creates a UDP gateway handler.
func NewHandler(conn net.PacketConn, keySet ECHDecryptor, users UserMatcher, whitelist WhitelistChecker, baseDomain string) *Handler {
	return &Handler{
		ListenConn: conn,
		KeySet:     keySet,
		Users:      users,
		Whitelist:  whitelist,
		BaseDomain: baseDomain,
		done:       make(chan struct{}),
	}
}

// maxSessions returns the configured max sessions, defaulting to DefaultMaxSessions.
func (h *Handler) maxSessions() int64 {
	if h.MaxSessions > 0 {
		return h.MaxSessions
	}
	return DefaultMaxSessions
}

func (h *Handler) currentKeySet() ECHDecryptor {
	if h == nil {
		return nil
	}
	if h.KeySource != nil {
		if current := h.KeySource.KeySet(); current != nil {
			return current
		}
	}
	return h.KeySet
}

// Serve runs the main read loop. It blocks until Stop is called or a fatal error occurs.
func (h *Handler) Serve() error {
	// Start the idle session reaper.
	go h.reapLoop()

	buf := make([]byte, MaxDatagramSize)
	for {
		select {
		case <-h.done:
			return nil
		default:
		}

		n, srcAddr, err := h.ListenConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-h.done:
				return nil // normal shutdown
			default:
				slog.Error("quic/handler: ReadFrom", "err", err)
				return err
			}
		}

		// Copy the datagram — buf is reused.
		datagram := make([]byte, n)
		copy(datagram, buf[:n])

		src := srcAddr.(*net.UDPAddr)

		// Use the listen address as destination for the five-tuple.
		// In TProxy mode, this would be the original destination from OOB.
		dst := h.ListenConn.LocalAddr().(*net.UDPAddr)

		ft := MakeFiveTuple(src, dst)

		// Look up existing session.
		if val, ok := h.sessions.Load(ft); ok {
			sess := val.(*Session)
			sess.Touch()
			h.forwardToUpstream(sess, datagram)
			continue
		}

		// New session — try to parse as QUIC Initial.
		go h.handleNewSession(ft, src, dst, datagram)
	}
}

// Stop gracefully shuts down the handler.
func (h *Handler) Stop() {
	h.doneOnce.Do(func() {
		close(h.done)
		h.ListenConn.Close()
	})

	// Close all active sessions.
	h.sessions.Range(func(key, val any) bool {
		h.closeSession(val.(*Session))
		return true
	})
}

// SessionCount returns the number of active sessions (for metrics/tests).
func (h *Handler) SessionCount() int {
	return int(h.sessionCount.Load())
}

func (h *Handler) closeSession(sess *Session) {
	if sess == nil {
		return
	}

	sess.cleanupOnce.Do(func() {
		sess.Close()
		h.sessions.Delete(sess.Key)
		h.sessionCount.Add(-1)
		slog.Info("quic/handler: session closed",
			"domain", sess.InnerSNI, "user", sess.UserID,
			"bytes_up", sess.BytesUp, "bytes_down", sess.BytesDown)
	})
}

func (h *Handler) prepareInitialPacket(innerRecord []byte, originalDatagram []byte) ([]byte, error) {
	handshake, err := HandshakeMessageFromRecord(innerRecord)
	if err != nil {
		return nil, fmt.Errorf("extract inner handshake: %w", err)
	}
	rewritten, err := RewriteInitialPacket(originalDatagram, handshake)
	if err != nil {
		return nil, fmt.Errorf("rewrite initial packet: %w", err)
	}
	return rewritten, nil
}

func (h *Handler) resolveRoute(ctx context.Context, innerSNI string) ([]*egress.EgressNode, []net.IP, error) {
	if h.Resolver == nil {
		return nil, nil, fmt.Errorf("resolver unavailable")
	}

	ips, err := h.Resolver.Resolve(ctx, innerSNI)
	if err != nil {
		return nil, nil, err
	}
	if len(ips) == 0 {
		return nil, nil, fmt.Errorf("no target IPs resolved for %q", innerSNI)
	}

	directNode := &egress.EgressNode{Name: "direct"}
	if h.Router == nil {
		return []*egress.EgressNode{directNode}, ips, nil
	}

	nodes := h.Router.RouteAll(innerSNI, ips[0])
	if len(nodes) == 0 {
		return []*egress.EgressNode{directNode}, ips, nil
	}

	return nodes, ips, nil
}

func (h *Handler) sessionFactory() DatagramSessionFactory {
	if h.SessionFactory != nil {
		return h.SessionFactory
	}
	return netPacketFactory{}
}

func normalizeRouteNode(node *egress.EgressNode) *egress.EgressNode {
	if node == nil {
		return nil
	}
	if node.IsDirect() && node.Name == "" {
		return &egress.EgressNode{Name: "direct"}
	}
	return node
}

func (h *Handler) openDirectSession(ctx context.Context, targetIPs []net.IP, targetPort uint16, firstDatagram []byte) (DatagramSession, net.IP, error) {
	if len(targetIPs) == 0 {
		return nil, nil, fmt.Errorf("no target IPs available for direct session")
	}

	var lastErr error
	for _, targetIP := range targetIPs {
		if targetIP == nil {
			lastErr = fmt.Errorf("missing target IP for direct session")
			continue
		}

		packetConn, err := h.sessionFactory().ListenPacket(ctx, "udp", ":0")
		if err != nil {
			return nil, nil, err
		}

		copiedIP := append(net.IP(nil), targetIP...)
		session := newDirectDatagramSession(packetConn, &net.UDPAddr{IP: copiedIP, Port: int(targetPort)})
		if err := session.Write(firstDatagram); err != nil {
			lastErr = err
			_ = session.Close()
			continue
		}
		return session, copiedIP, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no target IPs available for direct session")
	}
	return nil, nil, lastErr
}

func (h *Handler) openRoutedSession(
	ctx context.Context,
	innerSNI string,
	targetIP net.IP,
	targetPort uint16,
	firstDatagram []byte,
) (*egress.EgressNode, []net.IP, net.IP, DatagramSession, error) {
	nodes, ips, err := h.resolveRoute(ctx, innerSNI)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	directIPs := ips
	if targetIP != nil {
		directIPs = []net.IP{append(net.IP(nil), targetIP...)}
	}

	var lastErr error
	for _, candidate := range nodes {
		node := normalizeRouteNode(candidate)
		if node == nil {
			continue
		}

		if node.IsDirect() {
			session, selectedIP, err := h.openDirectSession(ctx, directIPs, targetPort, firstDatagram)
			if err != nil {
				lastErr = err
				continue
			}
			return node, ips, selectedIP, session, nil
		}

		if h.EgressClient == nil {
			lastErr = fmt.Errorf("egress client unavailable")
			continue
		}

		selectedIP := targetIP
		if selectedIP == nil && len(ips) > 0 {
			selectedIP = ips[0]
		}
		session, err := h.EgressClient.OpenSession(ctx, node, selectedIP, targetPort, firstDatagram)
		if err != nil {
			lastErr = err
			continue
		}
		return node, ips, selectedIP, session, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no usable route for %q", innerSNI)
	}
	return nil, ips, nil, nil, lastErr
}

// handleNewSession processes the first datagram of a new UDP flow.
func (h *Handler) handleNewSession(ft FiveTuple, src, dst *net.UDPAddr, datagram []byte) {
	// Check session capacity before doing expensive parsing.
	if h.sessionCount.Load() >= h.maxSessions() {
		h.DroppedSessions.Add(1)
		slog.Warn("quic/handler: session limit reached, dropping",
			"src", src, "limit", h.maxSessions())
		return
	}

	// Try parsing as QUIC Initial.
	parsed, err := ParseInitial(datagram)
	if err != nil {
		slog.Debug("quic/handler: not a QUIC Initial", "src", src, "err", err)
		return
	}

	if parsed.ClientHello == nil {
		slog.Debug("quic/handler: no ClientHello in Initial", "src", src)
		return
	}

	// Wrap the ClientHello in a TLS record for ech.Parse.
	record := WrapClientHelloRecord(parsed.ClientHello)
	echResult, err := ech.Parse(record)
	if err != nil {
		slog.Warn("quic/handler: ECH parse failed", "src", src, "err", err)
		return
	}

	if !echResult.HasECH {
		slog.Debug("quic/handler: no ECH in ClientHello", "src", src, "sni", echResult.OuterSNI)
		return
	}

	// Extract user hash from outer SNI.
	userHash := extractUserHash(echResult.OuterSNI, h.BaseDomain)
	if userHash == "" || !h.Users.IsValidUser(userHash) {
		slog.Warn("quic/handler: invalid user", "src", src, "outer_sni", echResult.OuterSNI)
		return
	}
	userID := h.Users.LookupUserID(userHash)

	// Decrypt ECH to get inner SNI and inner ClientHello record.
	keySet := h.currentKeySet()
	if keySet == nil {
		slog.Error("quic/handler: ECH keyset missing", "src", src, "outer_sni", echResult.OuterSNI)
		return
	}
	innerSNI, innerCHRecord, err := keySet.DecryptWithPublicName(echResult, echResult.OuterSNI)
	if err != nil {
		slog.Error("quic/handler: ECH decrypt failed", "src", src, "err", err)
		return
	}

	// Check whitelist.
	if !h.Whitelist.Contains(innerSNI) {
		slog.Warn("quic/handler: domain not whitelisted", "domain", innerSNI, "user", userID)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), sessionSetupTimeout)
	defer cancel()

	rewrittenInitial, err := h.prepareInitialPacket(innerCHRecord, datagram)
	if err != nil {
		slog.Error("quic/handler: initial rewrite failed", "domain", innerSNI, "err", err)
		return
	}

	routeNode, ips, selectedIP, upstreamSession, err := h.openRoutedSession(ctx, innerSNI, nil, uint16(dst.Port), rewrittenInitial)
	if err != nil {
		slog.Error("quic/handler: resolve/route failed", "domain", innerSNI, "err", err)
		return
	}

	if len(ips) == 0 {
		slog.Error("quic/handler: no target IPs resolved", "domain", innerSNI)
		_ = upstreamSession.Close()
		return
	}

	sess := &Session{
		Key:        ft,
		ClientAddr: src,
		Upstream:   upstreamSession,
		LastActive: time.Now(),
		InnerSNI:   innerSNI,
		UserID:     userID,
	}

	// Store session (race: another goroutine may have beaten us).
	if _, loaded := h.sessions.LoadOrStore(ft, sess); loaded {
		// Another goroutine already created the session — close ours.
		_ = upstreamSession.Close()
		return
	}
	h.sessionCount.Add(1)

	slog.Info("quic/handler: new session",
		"src", src, "domain", innerSNI, "user", userID, "route", routeNode.Name, "target_ip", selectedIP)

	// Start the reverse relay (upstream → client) in a goroutine.
	go h.relayFromUpstream(sess)
}

// forwardToUpstream sends a datagram from client to the upstream target.
func (h *Handler) forwardToUpstream(sess *Session, datagram []byte) {
	sess.mu.Lock()
	if sess.Closed {
		sess.mu.Unlock()
		return
	}
	upstream := sess.Upstream
	sess.mu.Unlock()

	err := upstream.Write(datagram)
	if err != nil {
		slog.Debug("quic/handler: write to upstream", "err", err)
		return
	}

	sess.mu.Lock()
	sess.BytesUp += int64(len(datagram))
	sess.mu.Unlock()
}

// relayFromUpstream reads datagrams from upstream and sends them back to the client.
func (h *Handler) relayFromUpstream(sess *Session) {
	defer h.closeSession(sess)

	for {
		readCtx, cancel := context.WithTimeout(context.Background(), IdleTimeout)
		payload, err := sess.Upstream.Read(readCtx)
		cancel()
		if err != nil {
			// Check if session is closed or we're shutting down.
			select {
			case <-h.done:
				return
			default:
			}
			if errors.Is(err, context.DeadlineExceeded) {
				slog.Debug("quic/handler: session idle timeout",
					"domain", sess.InnerSNI, "user", sess.UserID)
				return
			}
			if errors.Is(err, io.EOF) {
				return
			}
			slog.Debug("quic/handler: upstream read", "err", err)
			return
		}

		sess.Touch()

		// Send back to client through the listen socket.
		_, err = h.ListenConn.WriteTo(payload, sess.ClientAddr)
		if err != nil {
			slog.Debug("quic/handler: write to client", "err", err)
			return
		}

		sess.mu.Lock()
		sess.BytesDown += int64(len(payload))
		sess.mu.Unlock()
	}
}

// reapLoop periodically scans sessions and removes idle ones.
func (h *Handler) reapLoop() {
	ticker := time.NewTicker(SessionReapInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			now := time.Now()
			h.sessions.Range(func(key, val any) bool {
				sess := val.(*Session)
				sess.mu.Lock()
				idle := now.Sub(sess.LastActive) > IdleTimeout
				sess.mu.Unlock()
				if idle {
					slog.Debug("quic/handler: reaping idle session",
						"domain", sess.InnerSNI, "user", sess.UserID)
					h.closeSession(sess)
				}
				return true
			})
		}
	}
}

// extractUserHash extracts the user hash from an outer SNI like "<hash>.gw.<baseDomain>".
func extractUserHash(outerSNI, baseDomain string) string {
	// Expected format: <hash>.gw.<baseDomain>
	suffix := ".gw." + baseDomain
	if len(outerSNI) <= len(suffix) {
		return ""
	}
	if outerSNI[len(outerSNI)-len(suffix):] != suffix {
		return ""
	}
	return outerSNI[:len(outerSNI)-len(suffix)]
}
