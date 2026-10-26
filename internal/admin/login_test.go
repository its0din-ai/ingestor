package admin

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/auth"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/ratelimit"
	"github.com/encrypt0r/ingestor/internal/users"
)

// loginHandler initializes a Handler with the dashboard template loaded, so
// tests can cover both the success and failure (re-rendered form) paths.
func loginHandler(t *testing.T) *Handler {
	t.Helper()

	tmplPath, err := filepath.Abs(filepath.Join("..", "..", "templates", "admin.html"))
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("jwt_secret", strings.Repeat("k", 64))
	t.Setenv("upload_dir", "uploads")

	dir := t.TempDir()
	t.Chdir(dir)

	conn, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	cfg, err := config.Load(conn)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := auth.NewManager(cfg, conn)
	if err != nil {
		t.Fatal(err)
	}
	return &Handler{
		cfg:          cfg,
		conn:         conn,
		tmpl:         tmpl,
		sessions:     sessions,
		auditLog:     audit.New(conn),
		loginLimiter: ratelimit.New(loginLimit, loginWindow),
	}
}

// legacyHandler reproduces a pre-multi-user .env: no admin_username key and
// the password in admin_password.
func legacyHandler(t *testing.T) *Handler {
	t.Helper()
	t.Setenv("SINGLE_USER", "")
	t.Setenv("admin_username", "")
	t.Setenv("admin_password", "legacy-password-123")
	return loginHandler(t)
}

// singleUserHandler enables the explicit SINGLE_USER option while still
// configuring an admin_username.
func singleUserHandler(t *testing.T) *Handler {
	t.Helper()
	t.Setenv("SINGLE_USER", "true")
	t.Setenv("admin_username", "root")
	t.Setenv("admin_password", "single-password-123")
	return loginHandler(t)
}

func postLogin(rec *httptest.ResponseRecorder, h *Handler, body string) {
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Login(rec, req)
}

func hasSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" && c.Value != "" {
			return true
		}
	}
	return false
}

// TestLegacyPasswordOnlyLogin restores the old single-admin login request,
// which submitted only a password.
func TestLegacyPasswordOnlyLogin(t *testing.T) {
	h := legacyHandler(t)
	rec := httptest.NewRecorder()
	postLogin(rec, h, "password=legacy-password-123")

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard/" {
		t.Fatalf("redirect = %q, want /dashboard/", loc)
	}
	if !hasSessionCookie(rec) {
		t.Fatal("password-only login must issue a session cookie")
	}
}

// TestSingleUserPasswordOnlyLogin shows SINGLE_USER=true forces legacy login
// semantics even when admin_username is configured.
func TestSingleUserPasswordOnlyLogin(t *testing.T) {
	h := singleUserHandler(t)
	rec := httptest.NewRecorder()
	postLogin(rec, h, "password=single-password-123")

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body = %s", rec.Code, rec.Body.String())
	}
	if !hasSessionCookie(rec) {
		t.Fatal("single-user password-only login must issue a session cookie")
	}
}

// TestSingleUserRejectsRegularUserLogin ensures accounts created by the
// multi-user feature are ignored in single-user mode.
func TestSingleUserRejectsRegularUserLogin(t *testing.T) {
	h := singleUserHandler(t)
	if _, err := users.Create(h.conn, "alice", "strong-password-123", 0); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	postLogin(rec, h, "username=alice&password=strong-password-123")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (re-rendered login)", rec.Code)
	}
	if hasSessionCookie(rec) {
		t.Fatal("regular user must not get a session in single-user mode")
	}
	if !strings.Contains(rec.Body.String(), "invalid username or password") {
		t.Fatal("expected the generic login error")
	}
}
