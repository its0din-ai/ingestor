package auth

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/users"
)

func testKey() []byte {
	return bytes.Repeat([]byte("k"), 64)
}

func testUserID(t *testing.T, conn *sql.DB) int64 {
	t.Helper()
	u, err := users.Create(conn, "tester", "test-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestTokenIDLengthAndStability(t *testing.T) {
	id1 := TokenID("sometoken")
	id2 := TokenID("sometoken")
	id3 := TokenID("othertoken")
	if len(id1) != 6 {
		t.Fatalf("TokenID length = %d, want 6", len(id1))
	}
	if id1 != id2 {
		t.Fatal("TokenID must be deterministic per token")
	}
	if id1 == id3 {
		t.Fatal("different tokens must have different ids")
	}
}

func TestParseTokenRoundTrip(t *testing.T) {
	m := &Manager{key: testKey(), ttl: time.Hour}
	token, err := m.signToken("jti-123", 1)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := m.parseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ID != "jti-123" || claims.Subject != "1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestParseTokenWrongKey(t *testing.T) {
	a := &Manager{key: bytes.Repeat([]byte("a"), 64), ttl: time.Hour}
	b := &Manager{key: bytes.Repeat([]byte("b"), 64), ttl: time.Hour}
	token, err := a.signToken("jti", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.parseToken(token); err == nil {
		t.Fatal("expected error verifying with the wrong key")
	}
}

func TestParseTokenTampered(t *testing.T) {
	m := &Manager{key: testKey(), ttl: time.Hour}
	token, err := m.signToken("jti", 1)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["sub"] = "attacker"
	altered, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(altered) + "." + parts[2]
	if _, err := m.parseToken(tampered); err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestParseTokenRejectsNoneAlg(t *testing.T) {
	m := &Manager{key: testKey(), ttl: time.Hour}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","exp":9999999999}`))
	none := header + "." + payload + "."
	if _, err := m.parseToken(none); err == nil {
		t.Fatal("expected error for alg=none token")
	}
}

func TestParseTokenExpired(t *testing.T) {
	m := &Manager{key: testKey(), ttl: -time.Hour}
	token, err := m.signToken("jti", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.parseToken(token); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestSessionAllowlistAndLogoutDestroysToken(t *testing.T) {
	dir := t.TempDir()
	conn, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	m := &Manager{conn: conn, key: testKey(), ttl: time.Hour}
	uid := testUserID(t, conn)

	// Login: issue a session cookie.
	rec := httptest.NewRecorder()
	if err := m.StartSession(rec, uid); err != nil {
		t.Fatal(err)
	}
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session cookie set")
	}
	if session.Name != "session" {
		t.Fatalf("cookie name = %q, want session", session.Name)
	}

	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	req.AddCookie(session)
	if _, ok := m.sessionUser(req); !ok {
		t.Fatal("expected valid session after login")
	}

	// Logout: token must be destroyed even though its signature is valid.
	logoutRec := httptest.NewRecorder()
	m.EndSession(req, logoutRec)
	if _, ok := m.sessionUser(req); ok {
		t.Fatal("expected session to be invalid after logout (token destroyed)")
	}

	// A fresh cookie for a session that was never created must be invalid.
	if _, err := m.signToken("never-created", 1); err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: func() string {
		tok, _ := m.signToken("never-created", 1)
		return tok
	}()})
	if _, ok := m.sessionUser(req2); ok {
		t.Fatal("expected invalid session for jti not in allowlist")
	}
}

// TestLegacySessionResolvesToSuperadmin keeps admins signed in across the
// multi-user upgrade: session rows written by older versions have user_id 0
// (added by the schema migration) and the old JWT subject is "admin".
func TestLegacySessionResolvesToSuperadmin(t *testing.T) {
	dir := t.TempDir()
	conn, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if err := users.SeedSuperadmin(conn, "admin", "legacy-password-123", ""); err != nil {
		t.Fatal(err)
	}
	const jti = "legacy-jti"
	if err := db.CreateSession(conn, jti, 0, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	claims := jwt.RegisteredClaims{
		Subject:   "admin",
		ID:        jti,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(testKey())
	if err != nil {
		t.Fatal(err)
	}

	m := &Manager{conn: conn, key: testKey(), ttl: time.Hour}
	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	u, ok := m.sessionUser(req)
	if !ok {
		t.Fatal("legacy session should remain valid after the upgrade")
	}
	if u.Role != identity.RoleSuperadmin || u.Username != "admin" {
		t.Fatalf("legacy session user = %+v, want the superadmin", u)
	}
}

func TestLegacySessionRequiresSuperadmin(t *testing.T) {
	dir := t.TempDir()
	conn, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	const jti = "legacy-jti"
	if err := db.CreateSession(conn, jti, 0, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	claims := jwt.RegisteredClaims{
		Subject:   "admin",
		ID:        jti,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(testKey())
	if err != nil {
		t.Fatal(err)
	}

	m := &Manager{conn: conn, key: testKey(), ttl: time.Hour}
	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	if _, ok := m.sessionUser(req); ok {
		t.Fatal("ownerless session must be rejected when no superadmin exists")
	}
}

// TestSingleUserRejectsRegularSessions ignores accounts created by the
// multi-user feature while keeping the superadmin signed in.
func TestSingleUserRejectsRegularSessions(t *testing.T) {
	dir := t.TempDir()
	conn, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if err := users.SeedSuperadmin(conn, "admin", "legacy-password-123", ""); err != nil {
		t.Fatal(err)
	}
	su, err := users.Superadmin(conn)
	if err != nil {
		t.Fatal(err)
	}
	regular, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}

	m := &Manager{conn: conn, key: testKey(), ttl: time.Hour, singleUser: true}
	check := func(name string, userID int64) bool {
		t.Helper()
		jti := "jti-" + name
		if err := db.CreateSession(conn, jti, userID, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		token, err := m.signToken(jti, userID)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		_, ok := m.sessionUser(req)
		return ok
	}

	if !check("superadmin", su.ID) {
		t.Fatal("superadmin session must remain valid in single-user mode")
	}
	if check("regular", regular.ID) {
		t.Fatal("regular user session must be rejected in single-user mode")
	}
}

func TestExpiredSessionRowIsInvalid(t *testing.T) {
	dir := t.TempDir()
	conn, err := db.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	m := &Manager{conn: conn, key: testKey(), ttl: time.Hour}
	uid := testUserID(t, conn)
	token, err := m.signToken("expired-jti", uid)
	if err != nil {
		t.Fatal(err)
	}
	// Insert a session row that is already expired.
	if err := db.CreateSession(conn, "expired-jti", uid, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	if _, ok := m.sessionUser(req); ok {
		t.Fatal("expected expired session row to be rejected")
	}
}
