package controller

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// writeOp is an internal unit of work sent to the WriteSerializer goroutine.
type writeOp struct {
	fn     func(tx *sql.Tx) error
	result chan error
}

// SQLiteStore implements Store using modernc.org/sqlite with WAL mode
// and a WriteSerializer that funnels all writes through a single goroutine.
type SQLiteStore struct {
	readDB  *sql.DB
	writeDB *sql.DB
	writeCh chan writeOp
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewSQLiteStore opens (or creates) a SQLite database at dsn.
// It enforces WAL mode, busy_timeout, and synchronous=NORMAL, then
// starts the WriteSerializer goroutine.
func NewSQLiteStore(dsn string) (*SQLiteStore, error) {
	// Write connection — single dedicated connection for serialized writes.
	writeDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open write db: %w", err)
	}
	writeDB.SetMaxOpenConns(1)

	// Read connection pool — WAL allows concurrent reads.
	readDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		writeDB.Close()
		return nil, fmt.Errorf("open read db: %w", err)
	}
	readDB.SetMaxOpenConns(4)

	// Apply pragmas on the write connection.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-64000",
	}
	for _, p := range pragmas {
		if _, err := writeDB.Exec(p); err != nil {
			writeDB.Close()
			readDB.Close()
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}
	// Also set WAL, busy_timeout, and cache_size on the read pool.
	readPragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA cache_size=-64000",
	}
	for _, p := range readPragmas {
		if _, err := readDB.Exec(p); err != nil {
			writeDB.Close()
			readDB.Close()
			return nil, fmt.Errorf("read pragma %q: %w", p, err)
		}
	}

	if err := createTables(writeDB); err != nil {
		writeDB.Close()
		readDB.Close()
		return nil, err
	}

	s := &SQLiteStore{
		readDB:  readDB,
		writeDB: writeDB,
		writeCh: make(chan writeOp, 256),
		done:    make(chan struct{}),
	}
	s.wg.Add(1)
	go s.writeLoop()
	return s, nil
}

// createTables initializes the schema.
func createTables(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			user_id    TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			hash       TEXT UNIQUE NOT NULL,
			token      TEXT DEFAULT '',
			active     BOOLEAN DEFAULT TRUE,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS gateway_traffic (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id    TEXT NOT NULL,
			user_id    TEXT DEFAULT '',
			client_ip  TEXT NOT NULL,
			domain     TEXT NOT NULL,
			egress     TEXT NOT NULL,
			bytes_up   INTEGER NOT NULL,
			bytes_down INTEGER NOT NULL,
			start_time INTEGER NOT NULL,
			end_time   INTEGER NOT NULL,
			ech_success BOOLEAN NOT NULL,
			error_type TEXT DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_user   ON gateway_traffic(user_id, start_time)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_domain ON gateway_traffic(domain, start_time)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_egress ON gateway_traffic(egress, start_time)`,
		`CREATE INDEX IF NOT EXISTS idx_traffic_error  ON gateway_traffic(error_type, start_time)`,
		`CREATE TABLE IF NOT EXISTS dns_audit (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			node_id    TEXT NOT NULL,
			user_id    TEXT DEFAULT '',
			domain     TEXT NOT NULL,
			query_type TEXT NOT NULL,
			client_ip  TEXT NOT NULL,
			timestamp  INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_audit_user      ON dns_audit(user_id, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_audit_domain    ON dns_audit(domain, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_dns_audit_timestamp ON dns_audit(timestamp)`,
		`CREATE TABLE IF NOT EXISTS ech_key_state (
			id                       INTEGER PRIMARY KEY CHECK (id = 1),
			current_private_key_pem  BLOB NOT NULL,
			previous_private_key_pem BLOB DEFAULT '',
			updated_at               INTEGER NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("create table: %w", err)
		}
	}
	return nil
}

// writeLoop is the single writer goroutine. All INSERT/UPDATE operations
// are serialized here to prevent "database is locked" errors.
func (s *SQLiteStore) writeLoop() {
	defer s.wg.Done()
	for {
		select {
		case op := <-s.writeCh:
			tx, err := s.writeDB.Begin()
			if err != nil {
				op.result <- fmt.Errorf("begin tx: %w", err)
				continue
			}
			if err := op.fn(tx); err != nil {
				tx.Rollback()
				op.result <- err
				continue
			}
			op.result <- tx.Commit()
		case <-s.done:
			// Drain remaining ops before exiting.
			for {
				select {
				case op := <-s.writeCh:
					tx, err := s.writeDB.Begin()
					if err != nil {
						op.result <- err
						continue
					}
					if err := op.fn(tx); err != nil {
						tx.Rollback()
						op.result <- err
						continue
					}
					op.result <- tx.Commit()
				default:
					return
				}
			}
		}
	}
}

// write sends a write operation to the serializer and waits for the result.
func (s *SQLiteStore) write(fn func(tx *sql.Tx) error) error {
	result := make(chan error, 1)
	s.writeCh <- writeOp{fn: fn, result: result}
	return <-result
}

// --- User operations ---

func (s *SQLiteStore) CreateUser(_ context.Context, u *User) error {
	return s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(
			`INSERT INTO users (user_id, name, hash, token, active, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			u.UserID, u.Name, u.Hash, u.Token, u.Active, u.CreatedAt.Unix(),
		)
		return err
	})
}

func (s *SQLiteStore) GetUser(_ context.Context, userID string) (*User, error) {
	return s.scanUser(s.readDB.QueryRow(
		`SELECT user_id, name, hash, token, active, created_at FROM users WHERE user_id = ?`,
		userID,
	))
}

func (s *SQLiteStore) GetUserByHash(_ context.Context, hash string) (*User, error) {
	return s.scanUser(s.readDB.QueryRow(
		`SELECT user_id, name, hash, token, active, created_at FROM users WHERE hash = ?`,
		hash,
	))
}

func (s *SQLiteStore) ListUsers(_ context.Context, activeOnly bool) ([]*User, error) {
	query := `SELECT user_id, name, hash, token, active, created_at FROM users`
	if activeOnly {
		query += ` WHERE active = TRUE`
	}
	query += ` ORDER BY created_at`

	rows, err := s.readDB.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u, err := s.scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *SQLiteStore) UpdateUser(_ context.Context, u *User) error {
	return s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(
			`UPDATE users SET name=?, token=?, active=? WHERE user_id=?`,
			u.Name, u.Token, u.Active, u.UserID,
		)
		return err
	})
}

func (s *SQLiteStore) DeleteUser(_ context.Context, userID string) error {
	return s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM users WHERE user_id=?`, userID)
		return err
	})
}

// --- Traffic ---

func (s *SQLiteStore) InsertTraffic(_ context.Context, records []TrafficRecord) error {
	if len(records) == 0 {
		return nil
	}
	return s.write(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(
			`INSERT INTO gateway_traffic
			 (node_id, user_id, client_ip, domain, egress, bytes_up, bytes_down,
			  start_time, end_time, ech_success, error_type)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for i := range records {
			r := &records[i]
			_, err := stmt.Exec(
				r.NodeID, r.UserID, r.ClientIP, r.Domain, r.Egress,
				r.BytesUp, r.BytesDown,
				r.StartTime.Unix(), r.EndTime.Unix(),
				r.ECHSuccess, r.ErrorType,
			)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// --- DNS Audit ---

func (s *SQLiteStore) InsertDNSAudit(_ context.Context, records []DNSAuditRecord) error {
	if len(records) == 0 {
		return nil
	}
	return s.write(func(tx *sql.Tx) error {
		stmt, err := tx.Prepare(
			`INSERT INTO dns_audit (node_id, user_id, domain, query_type, client_ip, timestamp)
			 VALUES (?,?,?,?,?,?)`,
		)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for i := range records {
			r := &records[i]
			_, err := stmt.Exec(
				r.NodeID, r.UserID, r.Domain, r.QueryType, r.ClientIP, r.Timestamp.Unix(),
			)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// --- Aggregation ---

func (s *SQLiteStore) QueryTraffic(_ context.Context, f TrafficQueryFilter) ([]TrafficSummary, error) {
	query := `SELECT user_id, domain, egress, SUM(bytes_up), SUM(bytes_down), COUNT(*)
		FROM gateway_traffic WHERE 1=1`
	var args []any

	if f.UserID != "" {
		query += " AND user_id = ?"
		args = append(args, f.UserID)
	}
	if f.Domain != "" {
		query += " AND domain = ?"
		args = append(args, f.Domain)
	}
	if f.Egress != "" {
		query += " AND egress = ?"
		args = append(args, f.Egress)
	}
	if !f.StartTime.IsZero() {
		query += " AND start_time >= ?"
		args = append(args, f.StartTime.Unix())
	}
	if !f.EndTime.IsZero() {
		query += " AND end_time <= ?"
		args = append(args, f.EndTime.Unix())
	}
	query += " GROUP BY user_id, domain, egress"

	rows, err := s.readDB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []TrafficSummary
	for rows.Next() {
		var ts TrafficSummary
		if err := rows.Scan(&ts.UserID, &ts.Domain, &ts.Egress, &ts.BytesUp, &ts.BytesDown, &ts.Count); err != nil {
			return nil, err
		}
		results = append(results, ts)
	}
	return results, rows.Err()
}

// --- Retention ---

func (s *SQLiteStore) DeleteOldTraffic(_ context.Context, before time.Time) (int64, error) {
	var affected int64
	err := s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM gateway_traffic WHERE start_time < ?`, before.Unix())
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected, err
}

func (s *SQLiteStore) DeleteOldDNSAudit(_ context.Context, before time.Time) (int64, error) {
	var affected int64
	err := s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM dns_audit WHERE timestamp < ?`, before.Unix())
		if err != nil {
			return err
		}
		affected, _ = res.RowsAffected()
		return nil
	})
	return affected, err
}

// --- ECH key state ---

func (s *SQLiteStore) SaveECHKeyState(_ context.Context, state *ECHKeyState) error {
	if state == nil {
		return fmt.Errorf("ECH key state is required")
	}
	if len(state.CurrentPrivateKeyPEM) == 0 {
		return fmt.Errorf("current ECH private key is required")
	}

	updatedAt := state.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now()
	}

	currentPEM := append([]byte(nil), state.CurrentPrivateKeyPEM...)
	previousPEM := append([]byte(nil), state.PreviousPrivateKeyPEM...)

	return s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec(
			`INSERT INTO ech_key_state
			 (id, current_private_key_pem, previous_private_key_pem, updated_at)
			 VALUES (1, ?, ?, ?)
			 ON CONFLICT(id) DO UPDATE SET
			   current_private_key_pem = excluded.current_private_key_pem,
			   previous_private_key_pem = excluded.previous_private_key_pem,
			   updated_at = excluded.updated_at`,
			currentPEM,
			previousPEM,
			updatedAt.Unix(),
		)
		return err
	})
}

func (s *SQLiteStore) LoadECHKeyState(_ context.Context) (*ECHKeyState, error) {
	var state ECHKeyState
	var updatedAt int64

	err := s.readDB.QueryRow(
		`SELECT current_private_key_pem, previous_private_key_pem, updated_at
		 FROM ech_key_state WHERE id = 1`,
	).Scan(&state.CurrentPrivateKeyPEM, &state.PreviousPrivateKeyPEM, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	state.UpdatedAt = unixToTime(updatedAt)
	state.CurrentPrivateKeyPEM = append([]byte(nil), state.CurrentPrivateKeyPEM...)
	state.PreviousPrivateKeyPEM = append([]byte(nil), state.PreviousPrivateKeyPEM...)
	return &state, nil
}

// --- Lifecycle ---

func (s *SQLiteStore) Close() error {
	close(s.done)
	s.wg.Wait()
	slog.Info("sqlite_store_closed")
	err1 := s.writeDB.Close()
	err2 := s.readDB.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// --- internal helpers ---

type scannable interface {
	Scan(dest ...any) error
}

func (s *SQLiteStore) scanUser(row scannable) (*User, error) {
	var u User
	var createdAt int64
	err := row.Scan(&u.UserID, &u.Name, &u.Hash, &u.Token, &u.Active, &createdAt)
	if err != nil {
		return nil, err
	}
	u.CreatedAt = unixToTime(createdAt)
	return &u, nil
}

func (s *SQLiteStore) scanUserRow(rows *sql.Rows) (*User, error) {
	var u User
	var createdAt int64
	err := rows.Scan(&u.UserID, &u.Name, &u.Hash, &u.Token, &u.Active, &createdAt)
	if err != nil {
		return nil, err
	}
	u.CreatedAt = unixToTime(createdAt)
	return &u, nil
}
