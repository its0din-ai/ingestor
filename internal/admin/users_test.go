package admin

import (
	"database/sql"
	"encoding/json"
	"fmt"
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

func testHandler(t *testing.T) (*Handler, *sql.DB) {
	t.Helper()
	t.Setenv("jwt_secret", strings.Repeat("k", 64))
	t.Setenv("admin_password", "super-password-123")
	t.Setenv("admin_username", "admin")
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
	return &Handler{cfg: cfg, conn: conn, auditLog: audit.New(conn)}, conn
}

func superadmin(t *testing.T, conn *sql.DB) identity.User {
	t.Helper()
	list, err := users.List(conn)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range list {
		if u.Role == identity.RoleSuperadmin {
			return identity.User{ID: u.ID, Username: u.Username, Role: u.Role}
		}
	}
	t.Fatal("no superadmin seeded")
	return identity.User{}
}

func withUser(r *http.Request, u identity.User) *http.Request {
	return r.WithContext(identity.WithUser(r.Context(), u))
}

func TestCreateUserReturnsTokenOnce(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)

	body := `{"username":"alice","password":"strong-password-123","quota_mb":50}`
	req := withUser(httptest.NewRequest(http.MethodPost, "/dashboard/api/users/create", strings.NewReader(body)), su)
	rec := httptest.NewRecorder()
	h.CreateUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token string   `json:"token"`
		User  userData `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" || resp.User.Username != "alice" || resp.User.QuotaMB != 50 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	owner, ok := users.AuthenticateToken(conn, resp.Token)
	if !ok || owner.Username != "alice" {
		t.Fatalf("token owner = %+v, ok=%v", owner, ok)
	}
}

func TestDeleteUserRejectsSelf(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)

	body := fmt.Sprintf(`{"id":%d,"delete_data":true}`, su.ID)
	req := withUser(httptest.NewRequest(http.MethodPost, "/dashboard/api/users/delete", strings.NewReader(body)), su)
	rec := httptest.NewRecorder()
	h.DeleteUser(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

func TestSaveSettingsRejectsContentRootEscalation(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)
	before := h.cfg.UploadDirRelative()

	for _, dir := range []string{".", "uploads/users/2", "data"} {
		body := fmt.Sprintf(`{"upload_dir":%q}`, dir)
		req := withUser(httptest.NewRequest(http.MethodPost, "/dashboard/api/settings", strings.NewReader(body)), su)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.SaveSettingsJSON(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("upload_dir=%q status = %d, want 400; body = %s", dir, rec.Code, rec.Body.String())
		}
		if got := h.cfg.UploadDirRelative(); got != before {
			t.Fatalf("upload_dir changed to %q despite rejection", got)
		}
	}
}

func TestUpdateUserCannotResetPassword(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"id":%d,"quota_mb":5,"password":"attacker-chosen-123"}`, alice.ID)
	req := withUser(httptest.NewRequest(http.MethodPost, "/dashboard/api/users/update", strings.NewReader(body)), su)
	rec := httptest.NewRecorder()
	h.UpdateUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := users.Authenticate(conn, "alice", "attacker-chosen-123"); err == nil {
		t.Fatal("superadmin-supplied password must not authenticate")
	}
	if _, err := users.Authenticate(conn, "alice", "strong-password-123"); err != nil {
		t.Fatalf("existing password must keep working: %v", err)
	}
	updated, err := users.Get(conn, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.QuotaMB != 5 {
		t.Fatalf("quota = %d, want 5", updated.QuotaMB)
	}
}

func TestListUsersIncludesUsage(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)

	alice, err := users.Create(conn, "alice", "strong-password-123", 10)
	if err != nil {
		t.Fatal(err)
	}
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := withUser(httptest.NewRequest(http.MethodGet, "/dashboard/api/users", nil), su)
	rec := httptest.NewRecorder()
	h.ListUsers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Users []userData `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, u := range resp.Users {
		if u.Username == "alice" {
			if u.UsedBytes != 5 || u.Files != 1 || u.QuotaMB != 10 {
				t.Fatalf("alice usage = %+v", u)
			}
			return
		}
	}
	t.Fatal("alice missing from user list")
}

func TestDeleteUserFile(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)

	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "secret.txt"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"user_id":%d,"name":%q}`, alice.ID, name)
	req := withUser(httptest.NewRequest(http.MethodPost, "/dashboard/api/users/delete-file", strings.NewReader(body)), su)
	rec := httptest.NewRecorder()
	h.DeleteUserFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatalf("file still present, stat err = %v", err)
	}
}

func TestSuperadminReadsLegacyRootButNotUserFiles(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)

	root := h.cfg.UploadDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "legacy.txt"), []byte("legacy"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := withUser(httptest.NewRequest(http.MethodGet, "/dashboard/download?name=legacy.txt", nil), su)
	rec := httptest.NewRecorder()
	h.Download(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy file status = %d, want 200", rec.Code)
	}

	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "user-only.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	req = withUser(httptest.NewRequest(http.MethodGet, "/dashboard/download?name=user-only.txt", nil), su)
	rec = httptest.NewRecorder()
	h.Download(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("user file status = %d, want 404 (superadmin is scoped to the legacy root)", rec.Code)
	}
}

func TestListFilesScopedToUser(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mine.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := withUser(httptest.NewRequest(http.MethodGet, "/dashboard/api/files", nil), identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser})
	rec := httptest.NewRecorder()
	h.ListFiles(rec, req)
	var aliceResp struct {
		Files []fileInfo `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &aliceResp); err != nil {
		t.Fatal(err)
	}
	if len(aliceResp.Files) != 1 || aliceResp.Files[0].Name != "mine.txt" {
		t.Fatalf("alice files = %+v", aliceResp.Files)
	}

	req = withUser(httptest.NewRequest(http.MethodGet, "/dashboard/api/files", nil), su)
	rec = httptest.NewRecorder()
	h.ListFiles(rec, req)
	var suResp struct {
		Files []fileInfo `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &suResp); err != nil {
		t.Fatal(err)
	}
	if len(suResp.Files) != 0 {
		t.Fatalf("superadmin must not see user files, got %+v", suResp.Files)
	}
}
