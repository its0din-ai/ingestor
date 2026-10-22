package users

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/identity"
)

func testSecret() []byte {
	return bytes.Repeat([]byte("s"), 64)
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestSeedSuperadminReusesLegacyHash(t *testing.T) {
	conn := openTestDB(t)
	legacy, err := bcrypt.GenerateFromPassword([]byte("legacy-password-123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := SeedSuperadmin(conn, "admin", "", string(legacy)); err != nil {
		t.Fatal(err)
	}
	u, err := Authenticate(conn, "admin", "legacy-password-123")
	if err != nil {
		t.Fatalf("legacy password should authenticate: %v", err)
	}
	if u.Role != identity.RoleSuperadmin {
		t.Fatalf("role = %q, want superadmin", u.Role)
	}

	// A second seed must not overwrite the existing account.
	if err := SeedSuperadmin(conn, "admin", "different-password-123", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Authenticate(conn, "admin", "legacy-password-123"); err != nil {
		t.Fatalf("existing password must keep working: %v", err)
	}
}

func TestSeedSuperadminHashesEnvPassword(t *testing.T) {
	conn := openTestDB(t)
	if err := SeedSuperadmin(conn, "root", "env-password-123", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Authenticate(conn, "root", "env-password-123"); err != nil {
		t.Fatalf("env password should authenticate: %v", err)
	}
}

func TestCreateAndAuthenticate(t *testing.T) {
	conn := openTestDB(t)

	u, err := Create(conn, "alice", "strong-password-123", 100)
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != identity.RoleUser || u.QuotaMB != 100 {
		t.Fatalf("unexpected user: %+v", u)
	}

	got, err := Authenticate(conn, "alice", "strong-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != u.ID || got.Username != "alice" {
		t.Fatalf("authenticated user = %+v, want %+v", got, u)
	}

	if _, err := Authenticate(conn, "alice", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v, want ErrInvalidCredentials", err)
	}
	if _, err := Authenticate(conn, "nobody", "strong-password-123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user error = %v, want ErrInvalidCredentials", err)
	}
}

func TestCreateValidation(t *testing.T) {
	conn := openTestDB(t)
	if _, err := Create(conn, "alice", "strong-password-123", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(conn, "alice", "strong-password-456", 0); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate error = %v, want ErrUserExists", err)
	}
	if _, err := Create(conn, "ab", "strong-password-123", 0); !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("short username error = %v, want ErrInvalidUsername", err)
	}
	if _, err := Create(conn, "bob", "short", 0); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak password error = %v, want ErrWeakPassword", err)
	}
	if _, err := Create(conn, "carol", "strong-password-123", -1); !errors.Is(err, ErrInvalidQuota) {
		t.Fatalf("negative quota error = %v, want ErrInvalidQuota", err)
	}
}

func TestTokenLifecycle(t *testing.T) {
	conn := openTestDB(t)
	u, err := Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}

	token, info, err := CreateToken(conn, u.ID, "laptop", testSecret())
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := AuthenticateToken(conn, token)
	if !ok || owner.ID != u.ID || owner.Username != "alice" {
		t.Fatalf("token owner = %+v, ok=%v", owner, ok)
	}
	if _, ok := AuthenticateToken(conn, "not-a-token"); ok {
		t.Fatal("unknown token must not authenticate")
	}

	stored, err := Token(conn, u.ID, testSecret())
	if err != nil {
		t.Fatal(err)
	}
	if stored.TokenID != info.TokenID || stored.Label != "laptop" {
		t.Fatalf("token metadata = %+v, want id=%s label=laptop", stored, info.TokenID)
	}
	if stored.Token != token {
		t.Fatal("owner must be able to retrieve the token plaintext")
	}
	if wrong, err := Token(conn, u.ID, []byte("wrong-secret")); err != nil || wrong.Token != "" {
		t.Fatalf("token must not decrypt with the wrong secret: %+v, %v", wrong, err)
	}

	rotated, rotatedInfo, err := RotateToken(conn, u.ID, "", testSecret())
	if err != nil {
		t.Fatal(err)
	}
	if rotated == token {
		t.Fatal("rotated token must differ")
	}
	if _, ok := AuthenticateToken(conn, token); ok {
		t.Fatal("old token must be invalid after rotation")
	}
	if _, ok := AuthenticateToken(conn, rotated); !ok {
		t.Fatal("new token must authenticate")
	}
	if rotatedInfo.Label != TokenLabel {
		t.Fatalf("default label = %q, want %q", rotatedInfo.Label, TokenLabel)
	}
	if rotatedInfo.Token != rotated {
		t.Fatal("rotated token plaintext must be returned")
	}
}

func TestDisabledUserRejected(t *testing.T) {
	conn := openTestDB(t)
	u, err := Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := CreateToken(conn, u.ID, "", testSecret())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetDisabled(conn, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := Authenticate(conn, "alice", "strong-password-123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled login error = %v, want ErrInvalidCredentials", err)
	}
	if _, ok := AuthenticateToken(conn, token); ok {
		t.Fatal("disabled user's token must not authenticate")
	}
}

func TestUsageSkipsTempAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), make([]byte, 10), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), make([]byte, 20), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".ingestor-part.tmp"), make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "a.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}

	bytes, files, err := Usage(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bytes != 30 || files != 2 {
		t.Fatalf("usage = (%d bytes, %d files), want (30, 2)", bytes, files)
	}

	if bytes, files, err := Usage(filepath.Join(dir, "missing")); err != nil || bytes != 0 || files != 0 {
		t.Fatalf("missing dir usage = (%d, %d, %v)", bytes, files, err)
	}
}

func TestDeleteRemovesUserDataAndSessions(t *testing.T) {
	conn := openTestDB(t)
	uploadDir := t.TempDir()
	u, err := Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := UserDir(uploadDir, u.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CreateToken(conn, u.ID, "", testSecret()); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession(conn, "session-1", u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := Delete(conn, u.ID, uploadDir, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("user storage should be removed, stat err = %v", err)
	}
	if _, err := Get(conn, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("user should be gone, err = %v", err)
	}
	if _, _, err := db.SessionUser(conn, "session-1"); err == nil {
		t.Fatal("session row should be deleted")
	}
}
