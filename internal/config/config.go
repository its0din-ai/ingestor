package config

import (
	"database/sql"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"

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

type Config struct {
	mu   sync.RWMutex
	conn *sql.DB

	host          string
	port          int
	uploadDir     string
	maxUploadMB   int64
	quarantineExt []string
	bearerToken   string
	adminHash     []byte
}

func Load(conn *sql.DB) (*Config, error) {
	c := &Config{conn: conn}
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
		keyUploadDir, envOr("upload_dir", "uploads")); err != nil {
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

	c.mu.Lock()
	defer c.mu.Unlock()
	c.host = envOr("host", "127.0.0.1")
	c.port = port
	c.uploadDir = values[keyUploadDir]
	c.maxUploadMB = maxMB
	c.quarantineExt = splitExtensions(values[keyQuarantineExtensions])
	c.bearerToken = os.Getenv("bearer_token")
	c.adminHash = []byte(values[keyAdminPasswordHash])
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func writeEnv(key, value string) error {
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

func (c *Config) UploadDir() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uploadDir
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

func (c *Config) BearerToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bearerToken
}

func (c *Config) VerifyAdminPassword(password string) bool {
	c.mu.RLock()
	hash := c.adminHash
	c.mu.RUnlock()
	return len(hash) > 0 && bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

func (c *Config) SetUploadDir(dir string) error {
	return c.setSetting(keyUploadDir, dir)
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

func (c *Config) SetBearerToken(token string) error {
	if err := writeEnv("bearer_token", token); err != nil {
		return err
	}
	c.mu.Lock()
	c.bearerToken = token
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
