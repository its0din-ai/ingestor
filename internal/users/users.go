// Package users owns accounts, password hashing, per-user API tokens and
// storage accounting.
package users

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/encrypt0r/ingestor/internal/identity"
)

const (
	MinPasswordLen = 12
	MaxQuotaMB     = 1_000_000
	TokenLabel     = "api"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("username already exists")
	ErrNotFound           = errors.New("user not found")
	ErrInvalidUsername    = errors.New("username must be 3-32 characters: letters, digits, dot, dash or underscore")
	ErrWeakPassword       = fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	ErrInvalidQuota       = errors.New("quota must be between 0 and 1000000 MB")
	ErrLastSuperadmin     = errors.New("cannot remove the last superadmin")
	ErrNoSuperadmin       = errors.New("no superadmin account")
	ErrManySuperadmins    = errors.New("multiple superadmin accounts")
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`)

// dummyHash keeps unknown-user logins as expensive as real ones.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("ingestor-dummy-password"), bcrypt.DefaultCost)

type User struct {
	ID          int64
	Username    string
	Role        string
	QuotaMB     int64
	Disabled    bool
	CreatedAt   time.Time
	LastLoginAt sql.NullTime
}

type TokenInfo struct {
	ID        int64
	Label     string
	CreatedAt time.Time
	TokenID   string
	// Token is the plaintext value, populated only for the owning user's
	// display request. It is never stored in plaintext.
	Token string
}

// UserDir returns the storage root for a user. IDs are integers, so the path
// cannot escape the upload directory.
func UserDir(uploadDir string, userID int64) string {
	return filepath.Join(uploadDir, "users", strconv.FormatInt(userID, 10))
}

func ValidateUsername(username string) error {
	if !usernameRE.MatchString(username) {
		return ErrInvalidUsername
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < MinPasswordLen {
		return ErrWeakPassword
	}
	return nil
}

func validateQuota(quotaMB int64) error {
	if quotaMB < 0 || quotaMB > MaxQuotaMB {
		return ErrInvalidQuota
	}
	return nil
}

// SeedSuperadmin creates the superadmin account on first boot. It reuses the
// legacy admin_password_hash setting so existing installs keep their password,
// falling back to hashing the admin_password env value.
func SeedSuperadmin(conn *sql.DB, username, envPassword, legacyHash string) error {
	var n int
	if err := conn.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ?`, identity.RoleSuperadmin).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}

	hash := legacyHash
	if hash == "" {
		if envPassword == "" {
			slog.Warn("no admin_password configured; superadmin login disabled until one is set")
			return nil
		}
		h, err := bcrypt.GenerateFromPassword([]byte(envPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		hash = string(h)
	}

	if username == "" {
		username = "admin"
	}
	if err := ValidateUsername(username); err != nil {
		slog.Warn("invalid admin_username; falling back to admin", "username", username)
		username = "admin"
	}

	_, err := conn.Exec(
		`INSERT INTO users (username, password_hash, role, quota_mb) VALUES (?, ?, ?, 0)`,
		username, hash, identity.RoleSuperadmin,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		// A regular account already owns the configured name; keep the app
		// bootable and surface the conflict in the log.
		slog.Warn("admin_username is already taken by another account", "username", username)
		return nil
	}
	return err
}

// Authenticate verifies a username/password pair. Every failure returns the
// same error so callers cannot distinguish unknown users from bad passwords.
func Authenticate(conn *sql.DB, username, password string) (identity.User, error) {
	var (
		id   int64
		name string
		hash string
		role string
		dis  bool
	)
	err := conn.QueryRow(
		`SELECT id, username, password_hash, role, disabled FROM users WHERE username = ?`,
		strings.TrimSpace(username),
	).Scan(&id, &name, &hash, &role, &dis)
	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return identity.User{}, ErrInvalidCredentials
	}
	if err != nil {
		return identity.User{}, err
	}
	if dis || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return identity.User{}, ErrInvalidCredentials
	}
	if _, err := conn.Exec(`UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now(), id); err != nil {
		slog.Warn("failed to record last login", "err", err)
	}
	return identity.User{ID: id, Username: name, Role: role}, nil
}

func Get(conn *sql.DB, id int64) (User, error) {
	var u User
	err := conn.QueryRow(
		`SELECT id, username, role, quota_mb, disabled, created_at, last_login_at FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Username, &u.Role, &u.QuotaMB, &u.Disabled, &u.CreatedAt, &u.LastLoginAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func List(conn *sql.DB) ([]User, error) {
	rows, err := conn.Query(
		`SELECT id, username, role, quota_mb, disabled, created_at, last_login_at FROM users ORDER BY username`,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.QuotaMB, &u.Disabled, &u.CreatedAt, &u.LastLoginAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Superadmin returns the deployment's single superadmin identity. It fails
// closed when none or more than one exists, so callers never have to guess
// which admin a pre-multi-user session or login belongs to.
func Superadmin(conn *sql.DB) (identity.User, error) {
	rows, err := conn.Query(
		`SELECT id, username, role FROM users WHERE role = ? ORDER BY id LIMIT 2`,
		identity.RoleSuperadmin,
	)
	if err != nil {
		return identity.User{}, err
	}
	defer func() { _ = rows.Close() }()

	var out []identity.User
	for rows.Next() {
		var u identity.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role); err != nil {
			return identity.User{}, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return identity.User{}, err
	}
	switch len(out) {
	case 0:
		return identity.User{}, ErrNoSuperadmin
	case 1:
		return out[0], nil
	default:
		return identity.User{}, ErrManySuperadmins
	}
}

func Create(conn *sql.DB, username, password string, quotaMB int64) (User, error) {
	username = strings.TrimSpace(username)
	if err := ValidateUsername(username); err != nil {
		return User{}, err
	}
	if err := validatePassword(password); err != nil {
		return User{}, err
	}
	if err := validateQuota(quotaMB); err != nil {
		return User{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	res, err := conn.Exec(
		`INSERT INTO users (username, password_hash, role, quota_mb) VALUES (?, ?, ?, ?)`,
		username, string(hash), identity.RoleUser, quotaMB,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, ErrUserExists
		}
		return User{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, err
	}
	return Get(conn, id)
}

func SetQuota(conn *sql.DB, id, quotaMB int64) error {
	if err := validateQuota(quotaMB); err != nil {
		return err
	}
	return execUserUpdate(conn, `UPDATE users SET quota_mb = ? WHERE id = ?`, quotaMB, id)
}

func SetDisabled(conn *sql.DB, id int64, disabled bool) error {
	if err := execUserUpdate(conn, `UPDATE users SET disabled = ? WHERE id = ?`, disabled, id); err != nil {
		return err
	}
	if disabled {
		return DeleteSessionsForUser(conn, id)
	}
	return nil
}

func SetPassword(conn *sql.DB, id int64, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return execUserUpdate(conn, `UPDATE users SET password_hash = ? WHERE id = ?`, string(hash), id)
}

// Delete removes an account, its tokens and sessions, and optionally its
// storage. Audit records are retained as security history.
func Delete(conn *sql.DB, id int64, uploadDir string, deleteData bool) error {
	u, err := Get(conn, id)
	if err != nil {
		return err
	}
	if u.Role == identity.RoleSuperadmin {
		var n int
		if err := conn.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ?`, identity.RoleSuperadmin).Scan(&n); err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastSuperadmin
		}
	}

	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range []string{
		`DELETE FROM user_tokens WHERE user_id = ?`,
		`DELETE FROM sessions WHERE user_id = ?`,
		`DELETE FROM public_files WHERE user_id = ?`,
		`DELETE FROM upload_history WHERE user_id = ?`,
		`DELETE FROM users WHERE id = ?`,
	} {
		if _, err := tx.Exec(stmt, id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	if deleteData {
		dir := UserDir(uploadDir, id)
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("remove user storage: %w", err)
		}
	}
	return nil
}

func WipeStorage(uploadDir string, id int64) error {
	return os.RemoveAll(UserDir(uploadDir, id))
}

func DeleteSessionsForUser(conn *sql.DB, id int64) error {
	_, err := conn.Exec(`DELETE FROM sessions WHERE user_id = ?`, id)
	return err
}

func execUserUpdate(conn *sql.DB, query string, args ...any) error {
	res, err := conn.Exec(query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Usage returns the bytes and file count in dir, skipping in-flight temp files
// and symbolic links.
func Usage(dir string) (bytes int64, files int64, err error) {
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".ingestor-") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		bytes += info.Size()
		files++
		return nil
	})
	if os.IsNotExist(err) {
		return 0, 0, nil
	}
	return bytes, files, err
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// tokenCipher derives a 256-bit AES key from the application secret.
func tokenCipher(secret []byte) (cipher.AEAD, error) {
	if len(secret) == 0 {
		return nil, errors.New("missing token encryption key")
	}
	sum := sha256.Sum256(secret)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encryptToken(secret []byte, token string) (string, error) {
	aead, err := tokenCipher(secret)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := aead.Seal(nonce, nonce, []byte(token), nil)
	return base64.RawStdEncoding.EncodeToString(out), nil
}

func decryptToken(secret []byte, encoded string) (string, error) {
	aead, err := tokenCipher(secret)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw) < aead.NonceSize() {
		return "", errors.New("invalid token ciphertext")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// CreateToken issues a token for a user. The SHA-256 digest is used for
// authentication; the ciphertext (keyed from the app secret) lets the owner
// view the token again later.
func CreateToken(conn *sql.DB, userID int64, label string, secret []byte) (string, TokenInfo, error) {
	token, err := newToken()
	if err != nil {
		return "", TokenInfo{}, err
	}
	enc, err := encryptToken(secret, token)
	if err != nil {
		return "", TokenInfo{}, err
	}
	hash := hashToken(token)
	if strings.TrimSpace(label) == "" {
		label = TokenLabel
	}
	res, err := conn.Exec(
		`INSERT INTO user_tokens (user_id, token_hash, token_enc, label) VALUES (?, ?, ?, ?)`,
		userID, hash, enc, label,
	)
	if err != nil {
		return "", TokenInfo{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return "", TokenInfo{}, err
	}
	return token, TokenInfo{ID: id, Label: label, TokenID: hash[:6], Token: token, CreatedAt: time.Now()}, nil
}

// RotateToken replaces every existing token for a user with a fresh one.
func RotateToken(conn *sql.DB, userID int64, label string, secret []byte) (string, TokenInfo, error) {
	if _, err := conn.Exec(`DELETE FROM user_tokens WHERE user_id = ?`, userID); err != nil {
		return "", TokenInfo{}, err
	}
	return CreateToken(conn, userID, label, secret)
}

// AuthenticateToken resolves a plaintext token to its active owner.
func AuthenticateToken(conn *sql.DB, token string) (identity.User, bool) {
	if token == "" {
		return identity.User{}, false
	}
	var (
		id   int64
		name string
		role string
	)
	err := conn.QueryRow(
		`SELECT u.id, u.username, u.role
		   FROM user_tokens t JOIN users u ON u.id = t.user_id
		  WHERE t.token_hash = ? AND u.disabled = 0`,
		hashToken(token),
	).Scan(&id, &name, &role)
	if err != nil {
		return identity.User{}, false
	}
	return identity.User{ID: id, Username: name, Role: role}, true
}

// Token returns the most recent token for a user, decrypting the plaintext for
// display to its owner.
func Token(conn *sql.DB, userID int64, secret []byte) (TokenInfo, error) {
	var (
		t   TokenInfo
		hs  string
		enc string
	)
	err := conn.QueryRow(
		`SELECT id, label, created_at, token_hash, token_enc FROM user_tokens WHERE user_id = ? ORDER BY id DESC LIMIT 1`,
		userID,
	).Scan(&t.ID, &t.Label, &t.CreatedAt, &hs, &enc)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenInfo{}, ErrNotFound
	}
	if err != nil {
		return TokenInfo{}, err
	}
	if len(hs) >= 6 {
		t.TokenID = hs[:6]
	}
	if plain, err := decryptToken(secret, enc); err == nil {
		t.Token = plain
	}
	return t, nil
}

func Count(conn *sql.DB) (int64, error) {
	var n int64
	err := conn.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}
