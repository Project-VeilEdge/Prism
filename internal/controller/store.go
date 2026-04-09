package controller

import (
	"context"
	"time"
)

// User represents a user record in the store.
type User struct {
	UserID    string
	Name      string
	Hash      string // SHA256(user_id+":"+salt)[:12]
	Token     string
	Active    bool
	CreatedAt time.Time
}

// TrafficRecord represents a single gateway traffic metric.
type TrafficRecord struct {
	NodeID     string
	UserID     string
	ClientIP   string
	Domain     string
	Egress     string
	BytesUp    int64
	BytesDown  int64
	StartTime  time.Time
	EndTime    time.Time
	ECHSuccess bool
	ErrorType  string
}

// DNSAuditRecord represents a DNS query audit entry.
type DNSAuditRecord struct {
	NodeID    string
	UserID    string
	Domain    string
	QueryType string
	ClientIP  string
	Timestamp time.Time
}

// ECHKeyState is the durable controller-side snapshot of current and previous
// ECH private keys used to preserve the dual-key window across restarts.
type ECHKeyState struct {
	CurrentPrivateKeyPEM  []byte
	PreviousPrivateKeyPEM []byte
	UpdatedAt             time.Time
}

// TrafficSummary is the result of an aggregated traffic query.
type TrafficSummary struct {
	UserID    string
	Domain    string
	Egress    string
	BytesUp   int64
	BytesDown int64
	Count     int64
}

// TrafficQueryFilter specifies filters for aggregated traffic queries.
type TrafficQueryFilter struct {
	UserID    string
	Domain    string
	Egress    string
	StartTime time.Time
	EndTime   time.Time
}

// Store defines the persistence interface for the controller.
// Implementations must be safe for concurrent reads. Writes are serialized
// via WriteSerializer in the SQLite implementation.
type Store interface {
	// --- User management ---

	CreateUser(ctx context.Context, u *User) error
	GetUser(ctx context.Context, userID string) (*User, error)
	GetUserByHash(ctx context.Context, hash string) (*User, error)
	ListUsers(ctx context.Context, activeOnly bool) ([]*User, error)
	UpdateUser(ctx context.Context, u *User) error
	DeleteUser(ctx context.Context, userID string) error

	// --- Traffic ---

	InsertTraffic(ctx context.Context, records []TrafficRecord) error

	// --- DNS Audit ---

	InsertDNSAudit(ctx context.Context, records []DNSAuditRecord) error

	// --- Aggregation & Retention ---

	QueryTraffic(ctx context.Context, filter TrafficQueryFilter) ([]TrafficSummary, error)
	DeleteOldTraffic(ctx context.Context, before time.Time) (int64, error)
	DeleteOldDNSAudit(ctx context.Context, before time.Time) (int64, error)

	// --- Lifecycle ---

	Close() error
}
