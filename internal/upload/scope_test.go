package upload

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/users"
)

func testUploadHandler(t *testing.T) (*Handler, *sql.DB) {
	t.Helper()
	t.Setenv("jwt_secret", strings.Repeat("k", 64))
	t.Setenv("upload_dir", "uploads")
	t.Setenv("max_upload_mb", "10")

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
	return New(cfg, conn, audit.New(conn)), conn
}

func uploadRequest(u identity.User, size int) *http.Request {
	body := bytes.Repeat([]byte("a"), size)
	req := httptest.NewRequest(http.MethodPost, "/upload?name=test.txt", bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	return req.WithContext(identity.WithUser(req.Context(), u))
}

func TestUserUploadScopedAndQuotaEnforced(t *testing.T) {
	h, conn := testUploadHandler(t)
	u, err := users.Create(conn, "alice", "strong-password-123", 1)
	if err != nil {
		t.Fatal(err)
	}
	id := identity.User{ID: u.ID, Username: u.Username, Role: u.Role}

	// Over quota on the first upload.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, uploadRequest(id, 2*1024*1024))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload status = %d, want 413; body = %s", rec.Code, rec.Body.String())
	}

	// Within quota.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, uploadRequest(id, 512*1024))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	dir := users.UserDir(h.cfg.UploadDir(), u.ID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("user dir entries = %d, want 1", len(entries))
	}

	// A second upload that would exceed the remaining quota is refused.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, uploadRequest(id, 600*1024))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("second upload status = %d, want 413", rec.Code)
	}

	rows, err := db.ListUploads(conn, u.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].UserID != u.ID {
		t.Fatalf("upload records = %+v", rows)
	}
}

func TestLegacyIdentityUsesRootDir(t *testing.T) {
	h, _ := testUploadHandler(t)
	legacy := identity.User{Role: identity.RoleLegacy}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, uploadRequest(legacy, 16))
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy upload status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	entries, err := os.ReadDir(h.cfg.UploadDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("legacy root entries = %d, want 1", len(entries))
	}
}

func TestSuperadminUsesLegacyRoot(t *testing.T) {
	h, _ := testUploadHandler(t)
	su := identity.User{ID: 1, Username: "admin", Role: identity.RoleSuperadmin}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, uploadRequest(su, 16))
	if rec.Code != http.StatusOK {
		t.Fatalf("superadmin upload status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	entries, err := os.ReadDir(h.cfg.UploadDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("legacy root entries = %d, want 1", len(entries))
	}
}
