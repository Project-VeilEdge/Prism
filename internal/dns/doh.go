// Package dns implements the DoH endpoint with user authentication
// and ECH config injection for the Prism DNS server.
package dns

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// UserValidator checks whether a user hash is valid.
type UserValidator interface {
	IsValidUser(hash string) bool
}

// TokenValidator returns the bearer token for a given user hash.
// If the user has no token set, it returns "".
// DoHHandler uses this for optional double-auth.
type TokenValidator interface {
	GetUserToken(hash string) string
}

// QueryHandler processes a validated DNS query message and returns
// the response message. This is satisfied by the pipeline of
// Upstream + ECHInjector.
type QueryHandler interface {
	HandleQuery(userHash string, msg *dns.Msg) (*dns.Msg, error)
}

// AuditRecorder records successful, authenticated DNS queries.
type AuditRecorder interface {
	Record(AuditRecord)
}

// DoHHandler implements an HTTP handler for DNS-over-HTTPS (RFC 8484).
//
// Routing: /dns-query/<user_hash>
//
// Defense layers:
//  1. Accept header must contain "application/dns-message" — otherwise delegate to camouflage handler.
//  2. User hash must be valid — otherwise return DNS REFUSED (HTTP 200), never HTTP 401/403.
//  3. Bearer token double-auth — if user has a token, Authorization header must match.
type DoHHandler struct {
	Camouflage   http.Handler   // camouflage page for non-DoH requests
	Users        UserValidator  // validates user hash from URL
	Tokens       TokenValidator // optional: bearer token lookup for double-auth
	Auditor      AuditRecorder  // optional: reports successful DNS queries
	Limiter      *RateLimiter   // optional: per-IP rate limiter
	QueryHandler QueryHandler   // processes DNS queries
	PathPrefix   string         // e.g. "/dns-query/" (must end with /)
}

// ServeHTTP dispatches incoming requests through DoH defense layers.
func (h *DoHHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// --- Defense 1: Accept header check ---
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "application/dns-message") {
		h.Camouflage.ServeHTTP(w, r)
		return
	}

	// --- Extract user hash from path ---
	prefix := h.PathPrefix
	if prefix == "" {
		prefix = "/dns-query/"
	}
	if !strings.HasPrefix(r.URL.Path, prefix) {
		h.Camouflage.ServeHTTP(w, r)
		return
	}
	userHash := strings.TrimPrefix(r.URL.Path, prefix)
	userHash = strings.TrimRight(userHash, "/")

	if userHash == "" {
		h.Camouflage.ServeHTTP(w, r)
		return
	}

	// --- Defense 2: User hash validation ---
	if !h.Users.IsValidUser(userHash) {
		slog.Warn("doh_auth_failed", "hash", userHash, "remote", r.RemoteAddr)
		writeRefused(w, nil)
		return
	}

	// --- Defense 2.5: Per-IP rate limiting ---
	if h.Limiter != nil {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		if !h.Limiter.Allow(clientIP) {
			slog.Warn("doh_rate_limited", "ip", clientIP, "remote", r.RemoteAddr)
			writeRefused(w, nil)
			return
		}
	}

	// --- Defense 3: Bearer token double-auth ---
	if h.Tokens != nil {
		if userToken := h.Tokens.GetUserToken(userHash); userToken != "" {
			bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(bearer), []byte(userToken)) != 1 {
				slog.Warn("doh_token_failed", "hash", userHash, "remote", r.RemoteAddr)
				writeRefused(w, nil)
				return
			}
		}
	}

	// --- Parse DNS query ---
	var rawQuery []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		param := r.URL.Query().Get("dns")
		if param == "" {
			writeRefused(w, nil)
			return
		}
		rawQuery, err = base64.RawURLEncoding.DecodeString(param)
		if err != nil {
			slog.Debug("doh_bad_query", "err", err)
			writeRefused(w, nil)
			return
		}
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); !strings.Contains(ct, "application/dns-message") {
			writeRefused(w, nil)
			return
		}
		rawQuery, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			slog.Debug("doh_read_body_failed", "err", err)
			writeRefused(w, nil)
			return
		}
	default:
		writeRefused(w, nil)
		return
	}

	var msg dns.Msg
	if err := msg.Unpack(rawQuery); err != nil {
		slog.Debug("doh_unpack_failed", "err", err)
		writeRefused(w, nil)
		return
	}

	// --- Process query ---
	resp, err := h.QueryHandler.HandleQuery(userHash, &msg)
	if err != nil {
		slog.Error("doh_query_failed", "err", err, "user", userHash)
		writeServerFailure(w, &msg)
		return
	}

	h.recordAudit(userHash, r.RemoteAddr, &msg)
	writeDNSResponse(w, resp)
}

// writeRefused writes a DNS REFUSED response with HTTP 200.
// If origMsg is non-nil, the response copies its ID and Question section.
func writeRefused(w http.ResponseWriter, origMsg *dns.Msg) {
	resp := new(dns.Msg)
	if origMsg != nil {
		resp.SetRcode(origMsg, dns.RcodeRefused)
	} else {
		resp.Rcode = dns.RcodeRefused
	}
	writeDNSResponse(w, resp)
}

func writeServerFailure(w http.ResponseWriter, origMsg *dns.Msg) {
	resp := new(dns.Msg)
	if origMsg != nil {
		resp.SetRcode(origMsg, dns.RcodeServerFailure)
	} else {
		resp.Rcode = dns.RcodeServerFailure
	}
	writeDNSResponse(w, resp)
}

// writeDNSResponse serializes a dns.Msg and writes it as an HTTP response.
func writeDNSResponse(w http.ResponseWriter, msg *dns.Msg) {
	packed, err := msg.Pack()
	if err != nil {
		slog.Error("doh_pack_failed", "err", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(packed)
}

func (h *DoHHandler) recordAudit(userHash, remoteAddr string, msg *dns.Msg) {
	if h.Auditor == nil || msg == nil || len(msg.Question) == 0 {
		return
	}

	userID := ""
	if lookup, ok := h.Users.(interface{ LookupUserID(string) string }); ok {
		userID = lookup.LookupUserID(userHash)
	}

	clientIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		clientIP = remoteAddr
	}

	question := msg.Question[0]
	queryType := dns.TypeToString[question.Qtype]
	if queryType == "" {
		queryType = fmt.Sprintf("%d", question.Qtype)
	}

	h.Auditor.Record(AuditRecord{
		UserID:    userID,
		Domain:    strings.TrimSuffix(question.Name, "."),
		QueryType: queryType,
		ClientIP:  clientIP,
		Timestamp: time.Now(),
	})
}
