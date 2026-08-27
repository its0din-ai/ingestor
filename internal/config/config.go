package config

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"

	"github.com/encrypt0r/ingestor/internal/quarantine"
)

const (
	keyUploadDir            = "upload_dir"
	keyMaxUploadMB          = "max_upload_mb"
	keyQuarantineExtensions = "quarantine_extensions"
	keyAdminPasswordHash    = "admin_password_hash"
)

// envWriteMu serializes writes to the .env file so concurrent settings
// saves (e.g. bearer token updates) cannot tear the file.
var envWriteMu sync.Mutex

// BearerToken is a single upload credential. ExpiresAt zero means the token
// never expires; Label is an optional human-readable name for the sender.
type BearerToken struct {
	Token     string
	ExpiresAt time.Time
	Label     string
}

func (b BearerToken) Expired() bool {
	return !b.ExpiresAt.IsZero() && time.Now().After(b.ExpiresAt)
}

type Config struct {
	mu   sync.RWMutex
	conn *sql.DB

	// root is the project root (the app's working directory). The upload
	// directory is always constrained to live underneath it.
	root          string
	host          string
	port          int
	uploadDir     string
	maxUploadMB   int64
	quarantineExt []string
	bearerTokens  []BearerToken
	adminHash     []byte
}

func Load(conn *sql.DB) (*Config, error) {
	root, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	c := &Config{conn: conn, root: root}
	if _, err := c.JWTSecret(); err != nil {
		return nil, err
	}
	if err := c.seed(); err != nil {
		return nil, err
	}
	if err := c.refresh(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) seed() error {
	if _, err := c.conn.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`,
		keyUploadDir, c.normalizeUploadDir(envOr("upload_dir", "uploads"))); err != nil {
		return err
	}
	if _, err := c.conn.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`,
		keyMaxUploadMB, envOr("max_upload_mb", "2048")); err != nil {
		return err
	}
	if _, err := c.conn.Exec(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`,
		keyQuarantineExtensions, strings.Join(quarantine.DefaultBlacklist, ",")); err != nil {
		return err
	}
	return c.seedAdminHash()
}

func (c *Config) seedAdminHash() error {
	var existing string
	err := c.conn.QueryRow(`SELECT value FROM settings WHERE key = ?`, keyAdminPasswordHash).Scan(&existing)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}

	raw := os.Getenv("admin_password")
	if raw == "" {
		slog.Warn("admin_password not set in .env; admin login disabled until a password is configured")
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = c.conn.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)`, keyAdminPasswordHash, string(hash))
	return err
}

func (c *Config) refresh() error {
	rows, err := c.conn.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	values := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		values[k] = v
	}
	if err := rows.Err(); err != nil {
		return err
	}

	port, _ := strconv.Atoi(envOr("port", "8080"))
	maxMB, _ := strconv.ParseInt(values[keyMaxUploadMB], 10, 64)
	if maxMB <= 0 {
		maxMB = 2048
	}

	tokens := parseBearerTokens(os.Getenv("bearer_tokens"))
	if len(tokens) == 0 {
		// Legacy single-token config.
		if legacy := os.Getenv("bearer_token"); legacy != "" {
			tokens = []BearerToken{{Token: legacy}}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.host = envOr("host", "127.0.0.1")
	c.port = port
	c.uploadDir = c.normalizeUploadDir(values[keyUploadDir])
	c.maxUploadMB = maxMB
	c.quarantineExt = splitExtensions(values[keyQuarantineExtensions])
	c.bearerTokens = tokens
	c.adminHash = []byte(values[keyAdminPasswordHash])
	return nil
}

// JWTSecret returns the HS512 signing key. It requires a value of at least
// 64 bytes (raw string, or base64: prefixed for binary keys).
func (c *Config) JWTSecret() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("jwt_secret"))
	if raw == "" {
		return nil, errors.New("jwt_secret is not set in .env; generate one with: openssl rand -hex 64")
	}
	if strings.HasPrefix(raw, "base64:") {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw[len("base64:"):]))
		if err != nil {
			return nil, fmt.Errorf("jwt_secret base64 decode: %w", err)
		}
		if len(b) < 64 {
			return nil, fmt.Errorf("jwt_secret must be at least 64 bytes, got %d", len(b))
		}
		return b, nil
	}
	if len(raw) < 64 {
		return nil, fmt.Errorf("jwt_secret must be at least 64 bytes, got %d", len(raw))
	}
	return []byte(raw), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return fallback
	}
	return d
}

func writeEnv(key, value string) error {
	envWriteMu.Lock()
	defer envWriteMu.Unlock()
	values, err := godotenv.Read()
	if err != nil {
		values = map[string]string{}
	}
	values[key] = value
	return godotenv.Write(values, ".env")
}

func splitExtensions(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		ext := "." + strings.TrimPrefix(strings.ToLower(strings.TrimSpace(part)), ".")
		if ext != "." {
			out = append(out, ext)
		}
	}
	return out
}

// parseBearerTokens parses a comma-separated list of `[label=]token[|RFC3339]`.
func parseBearerTokens(raw string) []BearerToken {
	var out []BearerToken
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		bt := BearerToken{}
		if i := strings.LastIndex(part, "|"); i >= 0 {
			if exp, err := time.Parse(time.RFC3339, strings.TrimSpace(part[i+1:])); err == nil {
				bt.ExpiresAt = exp
				part = part[:i]
			}
		}
		if i := strings.Index(part, "="); i >= 0 {
			bt.Label = strings.TrimSpace(part[:i])
			part = strings.TrimSpace(part[i+1:])
		}
		bt.Token = strings.TrimSpace(part)
		if bt.Token == "" {
			continue
		}
		out = append(out, bt)
	}
	return out
}

func serializeBearerTokens(tokens []BearerToken) string {
	parts := make([]string, 0, len(tokens))
	for _, t := range tokens {
		s := t.Token
		if t.Label != "" {
			s = t.Label + "=" + s
		}
		if !t.ExpiresAt.IsZero() {
			s += "|" + t.ExpiresAt.UTC().Format(time.RFC3339)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

func (c *Config) Port() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.port
}

func (c *Config) Addr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.host + ":" + strconv.Itoa(c.port)
}

// WriteTimeout is the HTTP server's write deadline. It also covers reading
// the request body, so it must be long enough to stream large (multi-GiB)
// uploads over slow links. Set write_timeout to "0" to disable it.
func (c *Config) WriteTimeout() time.Duration {
	return durationEnv("write_timeout", 2*time.Hour)
}

// SessionTTL is the lifetime of an admin JWT session.
func (c *Config) SessionTTL() time.Duration {
	return durationEnv("session_ttl", 24*time.Hour)
}

// AuditRetention is how long audit entries are kept before pruning. Zero
// means never prune.
func (c *Config) AuditRetention() time.Duration {
	return durationEnv("audit_retention", 30*24*time.Hour)
}

// CookieSecure marks the session cookie as Secure (HTTPS only).
func (c *Config) CookieSecure() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("cookie_secure")), "true")
}

// UploadDir returns the resolved upload directory as an absolute path. It is
// always constrained to live inside the project root: an admin-supplied value
// like /etc resolves to <root>/etc, never to the OS root.
func (c *Config) UploadDir() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return filepath.Join(c.root, c.uploadDir)
}

// UploadDirRelative returns the stored, root-relative upload directory. It is
// used by the settings UI so the field round-trips idempotently.
func (c *Config) UploadDirRelative() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uploadDir
}

// normalizeUploadDir constrains an admin-supplied upload directory to the
// project root. Absolute paths (e.g. /etc) are made relative so they resolve
// to ./etc under the root, and any parent traversal is clamped back to the
// root itself. The returned value is a clean root-relative path.
func (c *Config) normalizeUploadDir(dir string) string {
	dir = strings.ReplaceAll(dir, "\\", "/")
	dir = strings.TrimSpace(dir)
	if dir == "" || dir == "/" {
		return "."
	}
	rel := strings.TrimLeft(dir, "/")
	clean := pathpkg.Clean(rel)
	if clean == "." || clean == "" {
		return "."
	}
	// Never allow escaping the project root.
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "."
	}
	return clean
}

func (c *Config) MaxUploadMB() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxUploadMB
}

func (c *Config) MaxUploadBytes() int64 {
	return c.MaxUploadMB() * 1024 * 1024
}

func (c *Config) QuarantineExtensions() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.quarantineExt...)
}

func (c *Config) BearerTokens() []BearerToken {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]BearerToken(nil), c.bearerTokens...)
}

// AuthenticateBearer validates a token against the configured list using
// constant-time comparison, ignoring expired entries.
func (c *Config) AuthenticateBearer(token string) (BearerToken, bool) {
	c.mu.RLock()
	tokens := c.bearerTokens
	c.mu.RUnlock()
	for _, t := range tokens {
		if t.Token == "" || t.Expired() {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(t.Token)) == 1 {
			return t, true
		}
	}
	return BearerToken{}, false
}

func (c *Config) VerifyAdminPassword(password string) bool {
	c.mu.RLock()
	hash := c.adminHash
	c.mu.RUnlock()
	return len(hash) > 0 && bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

func (c *Config) SetUploadDir(dir string) error {
	return c.setSetting(keyUploadDir, c.normalizeUploadDir(dir))
}

func (c *Config) SetMaxUploadMB(mb int64) error {
	return c.setSetting(keyMaxUploadMB, strconv.FormatInt(mb, 10))
}

func (c *Config) SetQuarantineExtensions(exts []string) error {
	parts := make([]string, 0, len(exts))
	for _, e := range exts {
		e = "." + strings.TrimPrefix(strings.ToLower(strings.TrimSpace(e)), ".")
		if e != "." {
			parts = append(parts, e)
		}
	}
	return c.setSetting(keyQuarantineExtensions, strings.Join(parts, ","))
}

func (c *Config) SetAdminPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return c.setSetting(keyAdminPasswordHash, string(hash))
}

// SetBearerTokens persists the token list to .env and refreshes memory.
func (c *Config) SetBearerTokens(tokens []BearerToken) error {
	if err := writeEnv("bearer_tokens", serializeBearerTokens(tokens)); err != nil {
		return err
	}
	c.mu.Lock()
	c.bearerTokens = append([]BearerToken(nil), tokens...)
	c.mu.Unlock()
	return nil
}

func (c *Config) setSetting(key, value string) error {
	_, err := c.conn.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return err
	}
	return c.refresh()
}
