package quic

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"prism/internal/ech"
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
	mu           sync.Mutex
	Key          FiveTuple
	ClientAddr   *net.UDPAddr   // original client address
	UpstreamConn net.PacketConn // connection to upstream server
	UpstreamAddr *net.UDPAddr   // upstream target address
	LastActive   time.Time
	BytesUp      int64
	BytesDown    int64
	InnerSNI     string
	UserID       string
	Closed       bool
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
	if s.UpstreamConn != nil {
		s.UpstreamConn.Close()
	}
}

// ECHDecryptor abstracts the ECH key set for decryption.
type ECHDecryptor interface {
	Decrypt(result *ech.ParseResult) (innerSNI string, innerCHRecord []byte, err error)
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

// Handler is the UDP Gateway that intercepts QUIC traffic,
// parses Initial packets for ECH, and forwards datagrams.
type Handler struct {
	// ListenConn is the UDP socket receiving inbound traffic (typically port 443).
	ListenConn net.PacketConn

	// ECH decryption.
	KeySet ECHDecryptor

	// User validation.
	Users      UserMatcher
	Whitelist  WhitelistChecker
	BaseDomain string

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
		sess := val.(*Session)
		sess.Close()
		h.sessions.Delete(key)
		h.sessionCount.Add(-1)
		return true
	})
}

// SessionCount returns the number of active sessions (for metrics/tests).
func (h *Handler) SessionCount() int {
	return int(h.sessionCount.Load())
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

	// Decrypt ECH to get inner SNI.
	innerSNI, _, err := h.KeySet.Decrypt(echResult)
	if err != nil {
		slog.Error("quic/handler: ECH decrypt failed", "src", src, "err", err)
		return
	}

	// Check whitelist.
	if !h.Whitelist.Contains(innerSNI) {
		slog.Warn("quic/handler: domain not whitelisted", "domain", innerSNI, "user", userID)
		return
	}

	// Dial upstream target (UDP to port 443 for QUIC).
	upstreamConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		slog.Error("quic/handler: upstream listen", "err", err)
		return
	}

	upstreamAddr := &net.UDPAddr{IP: net.ParseIP(innerSNI), Port: int(dst.Port)}
	// If innerSNI is a hostname (not an IP), we just forward to the original destination.
	// Real resolution would use the Resolver interface, but for QUIC transparent proxy
	// we forward to the original destination IP that the client was connecting to.
	upstreamAddr = &net.UDPAddr{IP: dst.IP, Port: dst.Port}

	sess := &Session{
		Key:          ft,
		ClientAddr:   src,
		UpstreamConn: upstreamConn,
		UpstreamAddr: upstreamAddr,
		LastActive:   time.Now(),
		InnerSNI:     innerSNI,
		UserID:       userID,
	}

	// Store session (race: another goroutine may have beaten us).
	if _, loaded := h.sessions.LoadOrStore(ft, sess); loaded {
		// Another goroutine already created the session — close ours.
		upstreamConn.Close()
		return
	}
	h.sessionCount.Add(1)

	slog.Info("quic/handler: new session",
		"src", src, "domain", innerSNI, "user", userID)

	// Forward the initial datagram to upstream.
	h.forwardToUpstream(sess, datagram)

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
	conn := sess.UpstreamConn
	addr := sess.UpstreamAddr
	sess.mu.Unlock()

	n, err := conn.WriteTo(datagram, addr)
	if err != nil {
		slog.Debug("quic/handler: write to upstream", "err", err)
		return
	}

	sess.mu.Lock()
	sess.BytesUp += int64(n)
	sess.mu.Unlock()
}

// relayFromUpstream reads datagrams from upstream and sends them back to the client.
func (h *Handler) relayFromUpstream(sess *Session) {
	defer func() {
		sess.Close()
		h.sessions.Delete(sess.Key)
		h.sessionCount.Add(-1)
		slog.Info("quic/handler: session closed",
			"domain", sess.InnerSNI, "user", sess.UserID,
			"bytes_up", sess.BytesUp, "bytes_down", sess.BytesDown)
	}()

	buf := make([]byte, MaxDatagramSize)
	for {
		// Set read deadline for idle timeout.
		sess.UpstreamConn.SetReadDeadline(time.Now().Add(IdleTimeout))

		n, _, err := sess.UpstreamConn.ReadFrom(buf)
		if err != nil {
			// Check if session is closed or we're shutting down.
			select {
			case <-h.done:
				return
			default:
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				slog.Debug("quic/handler: session idle timeout",
					"domain", sess.InnerSNI, "user", sess.UserID)
				return
			}
			slog.Debug("quic/handler: upstream read", "err", err)
			return
		}

		sess.Touch()

		// Send back to client through the listen socket.
		_, err = h.ListenConn.WriteTo(buf[:n], sess.ClientAddr)
		if err != nil {
			slog.Debug("quic/handler: write to client", "err", err)
			return
		}

		sess.mu.Lock()
		sess.BytesDown += int64(n)
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
					sess.Close()
					h.sessions.Delete(key)
					h.sessionCount.Add(-1)
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
