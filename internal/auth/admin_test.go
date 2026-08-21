package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/encrypt0r/ingestor/internal/db"
)

func testKey() []byte {
	return bytes.Repeat([]byte("k"), 64)
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
	token, err := m.signToken("jti-123")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := m.parseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ID != "jti-123" || claims.Subject != "admin" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestParseTokenWrongKey(t *testing.T) {
	a := &Manager{key: bytes.Repeat([]byte("a"), 64), ttl: time.Hour}
	b := &Manager{key: bytes.Repeat([]byte("b"), 64), ttl: time.Hour}
	token, err := a.signToken("jti")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.parseToken(token); err == nil {
		t.Fatal("expected error verifying with the wrong key")
	}
}

func TestParseTokenTampered(t *testing.T) {
	m := &Manager{key: testKey(), ttl: time.Hour}
	token, err := m.signToken("jti")
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
	token, err := m.signToken("jti")
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

	// Login: issue a session cookie.
	rec := httptest.NewRecorder()
	if err := m.StartSession(rec); err != nil {
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
	if !m.validSession(req) {
		t.Fatal("expected valid session after login")
	}

	// Logout: token must be destroyed even though its signature is valid.
	logoutRec := httptest.NewRecorder()
	m.EndSession(req, logoutRec)
	if m.validSession(req) {
		t.Fatal("expected session to be invalid after logout (token destroyed)")
	}

	// A fresh cookie for a session that was never created must be invalid.
	if _, err := m.signToken("never-created"); err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: func() string {
		tok, _ := m.signToken("never-created")
		return tok
	}()})
	if m.validSession(req2) {
		t.Fatal("expected invalid session for jti not in allowlist")
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
	token, err := m.signToken("expired-jti")
	if err != nil {
		t.Fatal(err)
	}
	// Insert a session row that is already expired.
	if err := db.CreateSession(conn, "expired-jti", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/dashboard/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	if m.validSession(req) {
		t.Fatal("expected expired session row to be rejected")
	}
}
