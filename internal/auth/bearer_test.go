package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/users"
)

// TestSingleUserBearerIgnoresPerUserTokens keeps only the legacy .env token
// list active when SINGLE_USER=true.
func TestSingleUserBearerIgnoresPerUserTokens(t *testing.T) {
	t.Setenv("jwt_secret", strings.Repeat("k", 64))
	t.Setenv("admin_username", "admin")
	t.Setenv("admin_password", "single-password-123")
	t.Setenv("SINGLE_USER", "true")
	t.Setenv("bearer_tokens", "legacy-token-value")
	t.Setenv("bearer_token", "")
	t.Setenv("upload_dir", "uploads")
	t.Chdir(t.TempDir())

	conn, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	cfg, err := config.Load(conn)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := cfg.JWTSecret()
	if err != nil {
		t.Fatal(err)
	}
	userToken, _, err := users.RotateToken(conn, alice.ID, users.TokenLabel, secret)
	if err != nil {
		t.Fatal(err)
	}

	h := Bearer(cfg, conn, audit.New(conn))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	send := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "/upload", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := send(userToken); code != http.StatusUnauthorized {
		t.Fatalf("per-user token status = %d, want 401 in single-user mode", code)
	}
	if code := send("legacy-token-value"); code != http.StatusOK {
		t.Fatalf("legacy token status = %d, want 200", code)
	}
}
