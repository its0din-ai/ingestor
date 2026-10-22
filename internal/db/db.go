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
	`CREATE TABLE IF NOT EXISTS public_files (
		stored_name TEXT PRIMARY KEY,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);`,
	`CREATE TABLE IF NOT EXISTS users (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
		password_hash TEXT NOT NULL,
		role          TEXT NOT NULL DEFAULT 'user',
		quota_mb      INTEGER NOT NULL DEFAULT 0,
		disabled      INTEGER NOT NULL DEFAULT 0,
		created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_login_at DATETIME
	);`,
	`CREATE TABLE IF NOT EXISTS user_tokens (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id    INTEGER NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		token_enc  TEXT NOT NULL DEFAULT '',
		label      TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
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
	if err := migrateStoredName(conn); err != nil {
		return err
	}
	if err := migrateAuditUserAgent(conn); err != nil {
		return err
	}
	if err := migrateUploadSource(conn); err != nil {
		return err
	}
	for _, table := range []string{"sessions", "upload_history", "audit_log"} {
		if err := migrateColumn(conn, table, "user_id", `INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if err := migrateColumn(conn, "user_tokens", "token_enc", `TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	if err := migratePublicFiles(conn); err != nil {
		return err
	}
	for _, stmt := range []string{
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_uploads_user ON upload_history(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_user ON user_tokens(user_id)`,
	} {
		if _, err := conn.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// migrateColumn adds column with the given definition when the table does not
// already have it.
func migrateColumn(conn *sql.DB, table, column, definition string) error {
	exists, err := columnExists(conn, table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = conn.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + definition)
	return err
}

// migratePublicFiles scopes public shares by owner. SQLite cannot change a
// primary key in place, so the table is rebuilt with (user_id, stored_name).
func migratePublicFiles(conn *sql.DB) error {
	exists, err := columnExists(conn, "public_files", "user_id")
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range []string{
		`CREATE TABLE public_files_new (
			user_id     INTEGER NOT NULL DEFAULT 0,
			stored_name TEXT NOT NULL,
			created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, stored_name)
		)`,
		`INSERT OR IGNORE INTO public_files_new (user_id, stored_name, created_at)
			SELECT 0, stored_name, created_at FROM public_files`,
		`DROP TABLE public_files`,
		`ALTER TABLE public_files_new RENAME TO public_files`,
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// columnExists reports whether table has column.
func columnExists(conn *sql.DB, table, column string) (bool, error) {
	rows, err := conn.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var def sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &def, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// migrateUploadSource adds the source column to upload_history if missing.
func migrateUploadSource(conn *sql.DB) error {
	exists, err := columnExists(conn, "upload_history", "source")
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = conn.Exec(`ALTER TABLE upload_history ADD COLUMN source TEXT NOT NULL DEFAULT ''`)
	return err
}

// migrateAuditUserAgent adds the user_agent column to audit_log if missing.
func migrateAuditUserAgent(conn *sql.DB) error {
	rows, err := conn.Query(`PRAGMA table_info(audit_log)`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	hasUserAgent := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var def sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &def, &pk); err != nil {
			return err
		}
		if name == "user_agent" {
			hasUserAgent = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasUserAgent {
		_, err = conn.Exec(`ALTER TABLE audit_log ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''`)
		return err
	}
	return nil
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

func CreateSession(conn *sql.DB, id string, userID int64, expiresAt time.Time) error {
	_, err := conn.Exec(`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`, id, userID, expiresAt)
	return err
}

func SessionExpiry(conn *sql.DB, id string) (time.Time, error) {
	var expiresAt time.Time
	err := conn.QueryRow(`SELECT expires_at FROM sessions WHERE id = ?`, id).Scan(&expiresAt)
	return expiresAt, err
}

// SessionUser returns the expiry and owner of a session row.
func SessionUser(conn *sql.DB, id string) (time.Time, int64, error) {
	var (
		expiresAt time.Time
		userID    int64
	)
	err := conn.QueryRow(`SELECT expires_at, user_id FROM sessions WHERE id = ?`, id).Scan(&expiresAt, &userID)
	return expiresAt, userID, err
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

// MarkPublic registers a stored file as publicly shareable via /pub.
func MarkPublic(conn *sql.DB, userID int64, storedName string) error {
	_, err := conn.Exec(`INSERT OR IGNORE INTO public_files (user_id, stored_name) VALUES (?, ?)`, userID, storedName)
	return err
}

// MarkPrivate revokes public access for a stored file.
func MarkPrivate(conn *sql.DB, userID int64, storedName string) error {
	_, err := conn.Exec(`DELETE FROM public_files WHERE user_id = ? AND stored_name = ?`, userID, storedName)
	return err
}

// IsPublic reports whether a stored file is marked publicly shareable.
func IsPublic(conn *sql.DB, userID int64, storedName string) bool {
	var n int
	err := conn.QueryRow(`SELECT COUNT(*) FROM public_files WHERE user_id = ? AND stored_name = ?`, userID, storedName).Scan(&n)
	return err == nil && n > 0
}

type UploadRecord struct {
	UserID       int64
	OriginalName string
	StoredName   string
	FileSize     int64
	Quarantined  bool
	RemoteAddr   string
	Source       string
	CreatedAt    time.Time
}

func InsertUpload(conn *sql.DB, r UploadRecord) error {
	_, err := conn.Exec(
		`INSERT INTO upload_history (user_id, original_name, stored_name, file_size, quarantined, remote_addr, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.UserID, r.OriginalName, r.StoredName, r.FileSize, r.Quarantined, r.RemoteAddr, r.Source, r.CreatedAt,
	)
	return err
}

// UploaderIP returns the remote address that uploaded the file stored under
// storedName, or "" if no matching record exists.
func UploaderIP(conn *sql.DB, userID int64, storedName string) (string, error) {
	var ip string
	err := conn.QueryRow(
		`SELECT remote_addr FROM upload_history WHERE user_id = ? AND stored_name = ? ORDER BY id DESC LIMIT 1`,
		userID, storedName,
	).Scan(&ip)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return ip, err
}

// UploadSource returns the source ("api" or "browser") of the stored file, or
// "" if no matching record exists.
func UploadSource(conn *sql.DB, userID int64, storedName string) (string, error) {
	var src string
	err := conn.QueryRow(
		`SELECT source FROM upload_history WHERE user_id = ? AND stored_name = ? ORDER BY id DESC LIMIT 1`,
		userID, storedName,
	).Scan(&src)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return src, err
}

// DeleteUserUploads removes all upload history and public shares for a user.
func DeleteUserUploads(conn *sql.DB, userID int64) error {
	if _, err := conn.Exec(`DELETE FROM upload_history WHERE user_id = ?`, userID); err != nil {
		return err
	}
	_, err := conn.Exec(`DELETE FROM public_files WHERE user_id = ?`, userID)
	return err
}

// DeleteUploadRecord removes the history rows for a stored file.
func DeleteUploadRecord(conn *sql.DB, userID int64, storedName string) error {
	_, err := conn.Exec(`DELETE FROM upload_history WHERE user_id = ? AND stored_name = ?`, userID, storedName)
	return err
}

// SetUploadQuarantined updates the quarantine flag of the stored file name.
// It is used when an admin quarantines or releases a file from the UI.
func SetUploadQuarantined(conn *sql.DB, userID int64, storedName string, quarantined bool) error {
	_, err := conn.Exec(
		`UPDATE upload_history SET quarantined = ? WHERE user_id = ? AND stored_name = ?`,
		quarantined, userID, storedName,
	)
	return err
}

// ListUploads returns recent uploads. userID < 0 returns records for every
// owner; otherwise only that user's rows are returned.
func ListUploads(conn *sql.DB, userID int64, limit, offset int) ([]UploadRecord, error) {
	query := `SELECT user_id, original_name, stored_name, file_size, quarantined, remote_addr, created_at FROM upload_history`
	args := []any{}
	if userID >= 0 {
		query += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []UploadRecord
	for rows.Next() {
		var u UploadRecord
		if err := rows.Scan(&u.UserID, &u.OriginalName, &u.StoredName, &u.FileSize, &u.Quarantined, &u.RemoteAddr, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type AuditRecord struct {
	ID         int64
	UserID     int64
	Action     string
	Summary    string
	Detail     string
	RemoteAddr string
	UserAgent  string
	CreatedAt  time.Time
}

func InsertAudit(conn *sql.DB, r AuditRecord) error {
	_, err := conn.Exec(
		`INSERT INTO audit_log (user_id, action, summary, detail, remote_addr, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.UserID, r.Action, r.Summary, r.Detail, r.RemoteAddr, r.UserAgent, r.CreatedAt,
	)
	return err
}

// ListAudit returns audit rows. userID < 0 returns every row; otherwise only
// that user's events.
func ListAudit(conn *sql.DB, userID int64, limit, offset int) ([]AuditRecord, error) {
	query := `SELECT id, user_id, action, summary, detail, remote_addr, user_agent, created_at FROM audit_log`
	args := []any{}
	if userID >= 0 {
		query += ` WHERE user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []AuditRecord
	for rows.Next() {
		var a AuditRecord
		if err := rows.Scan(&a.ID, &a.UserID, &a.Action, &a.Summary, &a.Detail, &a.RemoteAddr, &a.UserAgent, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func CountAudit(conn *sql.DB, userID int64) (int64, error) {
	var n int64
	if userID < 0 {
		err := conn.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&n)
		return n, err
	}
	err := conn.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}
