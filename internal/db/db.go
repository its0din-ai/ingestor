package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS sessions (
		id         TEXT PRIMARY KEY,
		expires_at DATETIME NOT NULL
	);`,
	`CREATE TABLE IF NOT EXISTS upload_history (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		original_name TEXT NOT NULL,
		stored_name   TEXT NOT NULL DEFAULT '',
		file_size     INTEGER NOT NULL,
		quarantined   BOOLEAN NOT NULL DEFAULT 0,
		remote_addr   TEXT NOT NULL,
		created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);`,
	`CREATE TABLE IF NOT EXISTS audit_log (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		action      TEXT NOT NULL,
		summary     TEXT NOT NULL,
		detail      TEXT NOT NULL DEFAULT '',
		remote_addr TEXT NOT NULL,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);`,
}

func Open(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}

	// WAL allows concurrent readers alongside a single writer; busy_timeout
	// makes writers wait instead of failing with SQLITE_BUSY; the pool is
	// capped at 1 so every statement shares one connection and lock
	// contention is impossible.
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	conn.SetMaxOpenConns(1)

	if err := migrate(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func migrate(conn *sql.DB) error {
	for _, stmt := range migrations {
		if _, err := conn.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return migrateStoredName(conn)
}

func migrateStoredName(conn *sql.DB) error {
	rows, err := conn.Query(`PRAGMA table_info(upload_history)`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	hasStoredName := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var def sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &def, &pk); err != nil {
			return err
		}
		if name == "stored_name" {
			hasStoredName = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if !hasStoredName {
		_, err = conn.Exec(`ALTER TABLE upload_history ADD COLUMN stored_name TEXT NOT NULL DEFAULT ''`)
		return err
	}
	return nil
}

func CreateSession(conn *sql.DB, id string, expiresAt time.Time) error {
	_, err := conn.Exec(`INSERT INTO sessions (id, expires_at) VALUES (?, ?)`, id, expiresAt)
	return err
}

func SessionExpiry(conn *sql.DB, id string) (time.Time, error) {
	var expiresAt time.Time
	err := conn.QueryRow(`SELECT expires_at FROM sessions WHERE id = ?`, id).Scan(&expiresAt)
	return expiresAt, err
}

func DeleteSession(conn *sql.DB, id string) error {
	_, err := conn.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteAllSessions invalidates every active session (e.g. after an admin
// password change).
func DeleteAllSessions(conn *sql.DB) error {
	_, err := conn.Exec(`DELETE FROM sessions`)
	return err
}

// DeleteExpiredSessions removes sessions whose expiry has passed.
func DeleteExpiredSessions(conn *sql.DB, now time.Time) error {
	_, err := conn.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now)
	return err
}

// DeleteAuditOlderThan removes audit entries older than the given cutoff.
func DeleteAuditOlderThan(conn *sql.DB, cutoff time.Time) error {
	_, err := conn.Exec(`DELETE FROM audit_log WHERE created_at < ?`, cutoff)
	return err
}

type UploadRecord struct {
	OriginalName string
	StoredName   string
	FileSize     int64
	Quarantined  bool
	RemoteAddr   string
	CreatedAt    time.Time
}

func InsertUpload(conn *sql.DB, r UploadRecord) error {
	_, err := conn.Exec(
		`INSERT INTO upload_history (original_name, stored_name, file_size, quarantined, remote_addr, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		r.OriginalName, r.StoredName, r.FileSize, r.Quarantined, r.RemoteAddr, r.CreatedAt,
	)
	return err
}

// UploaderIP returns the remote address that uploaded the file stored under
// storedName, or "" if no matching record exists.
func UploaderIP(conn *sql.DB, storedName string) (string, error) {
	var ip string
	err := conn.QueryRow(
		`SELECT remote_addr FROM upload_history WHERE stored_name = ? ORDER BY id DESC LIMIT 1`,
		storedName,
	).Scan(&ip)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return ip, err
}

// SetUploadQuarantined updates the quarantine flag of the stored file name.
// It is used when an admin quarantines or releases a file from the UI.
func SetUploadQuarantined(conn *sql.DB, storedName string, quarantined bool) error {
	_, err := conn.Exec(
		`UPDATE upload_history SET quarantined = ? WHERE stored_name = ?`,
		quarantined, storedName,
	)
	return err
}

func ListUploads(conn *sql.DB, limit, offset int) ([]UploadRecord, error) {
	rows, err := conn.Query(
		`SELECT original_name, stored_name, file_size, quarantined, remote_addr, created_at FROM upload_history ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []UploadRecord
	for rows.Next() {
		var u UploadRecord
		if err := rows.Scan(&u.OriginalName, &u.StoredName, &u.FileSize, &u.Quarantined, &u.RemoteAddr, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type AuditRecord struct {
	ID         int64
	Action     string
	Summary    string
	Detail     string
	RemoteAddr string
	CreatedAt  time.Time
}

func InsertAudit(conn *sql.DB, r AuditRecord) error {
	_, err := conn.Exec(
		`INSERT INTO audit_log (action, summary, detail, remote_addr, created_at) VALUES (?, ?, ?, ?, ?)`,
		r.Action, r.Summary, r.Detail, r.RemoteAddr, r.CreatedAt,
	)
	return err
}

func ListAudit(conn *sql.DB, limit, offset int) ([]AuditRecord, error) {
	rows, err := conn.Query(
		`SELECT id, action, summary, detail, remote_addr, created_at FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []AuditRecord
	for rows.Next() {
		var a AuditRecord
		if err := rows.Scan(&a.ID, &a.Action, &a.Summary, &a.Detail, &a.RemoteAddr, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func CountAudit(conn *sql.DB) (int64, error) {
	var n int64
	err := conn.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
	return n, err
}
