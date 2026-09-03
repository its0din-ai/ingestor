package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestParseBearerTokens(t *testing.T) {
	tests := []struct {
		raw  string
		want int
	}{
		{"", 0},
		{"token1", 1},
		{"a=token1|2027-06-01T00:00:00Z", 1},
		{"a=token1|2027-06-01T00:00:00Z, b=token2", 2},
		{"token1, token2|2027-06-01T00:00:00Z", 2},
		{"  , token1 ,,", 1},
		{"no-expiry-but-pipe|", 1}, // unparseable expiry ignored
		{"badpipe|=notadate", 1},   // token kept, no label parse
	}
	for _, tt := range tests {
		got := parseBearerTokens(tt.raw)
		if len(got) != tt.want {
			t.Errorf("parseBearerTokens(%q) = %d tokens, want %d", tt.raw, len(got), tt.want)
		}
	}
}

func TestParseBearerTokenFields(t *testing.T) {
	exp := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	got := parseBearerTokens("alice=sekret|2027-06-01T00:00:00Z")
	if len(got) != 1 {
		t.Fatalf("got %d tokens, want 1", len(got))
	}
	tok := got[0]
	if tok.Token != "sekret" || tok.Label != "alice" {
		t.Fatalf("unexpected fields: %+v", tok)
	}
	if !tok.ExpiresAt.Equal(exp) {
		t.Fatalf("expires = %v, want %v", tok.ExpiresAt, exp)
	}
	if tok.Expired() {
		t.Fatal("future token must not be expired")
	}
}

func TestAuthenticateBearer(t *testing.T) {
	now := time.Now()
	c := &Config{bearerTokens: []BearerToken{
		{Token: "indefinite"},
		{Token: "expired", ExpiresAt: now.Add(-time.Minute)},
		{Token: "future", ExpiresAt: now.Add(time.Hour), Label: "contractor"},
	}}

	if _, ok := c.AuthenticateBearer("indefinite"); !ok {
		t.Fatal("expected indefinite token to match")
	}
	if _, ok := c.AuthenticateBearer("expired"); ok {
		t.Fatal("expected expired token to be rejected")
	}
	matched, ok := c.AuthenticateBearer("future")
	if !ok || matched.Label != "contractor" {
		t.Fatalf("expected future token match with label, got %+v, %v", matched, ok)
	}
	if _, ok := c.AuthenticateBearer("missing"); ok {
		t.Fatal("expected unknown token to be rejected")
	}
}

func TestSerializeRoundTrip(t *testing.T) {
	exp := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	in := []BearerToken{
		{Token: "t1"},
		{Token: "t2", Label: "bob", ExpiresAt: exp},
	}
	out := parseBearerTokens(serializeBearerTokens(in))
	if len(out) != 2 {
		t.Fatalf("round-trip produced %d tokens, want 2", len(out))
	}
	if out[1].Label != "bob" || out[1].Token != "t2" || !out[1].ExpiresAt.Equal(exp) {
		t.Fatalf("round-trip mismatch: %+v", out[1])
	}
}

func TestJWTSecretValidation(t *testing.T) {
	t.Setenv("jwt_secret", "")
	if _, err := (&Config{}).JWTSecret(); err == nil {
		t.Fatal("expected error for missing jwt_secret")
	}
	t.Setenv("jwt_secret", strings.Repeat("x", 63))
	if _, err := (&Config{}).JWTSecret(); err == nil {
		t.Fatal("expected error for short jwt_secret")
	}
	t.Setenv("jwt_secret", strings.Repeat("x", 64))
	if _, err := (&Config{}).JWTSecret(); err != nil {
		t.Fatalf("expected valid 64-byte secret, got %v", err)
	}
}

func TestJWTSecretBase64(t *testing.T) {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte(i)
	}
	t.Setenv("jwt_secret", "base64:"+base64.StdEncoding.EncodeToString(raw))
	got, err := (&Config{}).JWTSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 64 {
		t.Fatalf("key length = %d, want 64", len(got))
	}

	// 48-byte base64 key is too short.
	short := make([]byte, 48)
	t.Setenv("jwt_secret", "base64:"+base64.StdEncoding.EncodeToString(short))
	if _, err := (&Config{}).JWTSecret(); err == nil {
		t.Fatal("expected error for short base64 key")
	}
}

func TestNormalizeUploadDir(t *testing.T) {
	c := &Config{root: "/srv/ingestor"}
	tests := []struct{ in, want string }{
		{"uploads", "uploads"},
		{"/etc", "etc"},
		{"etc", "etc"},
		{"uploads/", "uploads"},
		{"../../etc", "."},
		{"../escape", "."},
		{"..", "."},
		{".", "."},
		{"/", "."},
		{"", "."},
		{`..\..\evil`, "."},
		{"/abs/path/here", "abs/path/here"},
		{"a/../b", "b"},
	}
	for _, tt := range tests {
		if got := c.normalizeUploadDir(tt.in); got != tt.want {
			t.Errorf("normalizeUploadDir(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestUploadDirStaysInRoot(t *testing.T) {
	c := &Config{root: "/srv/ingestor", uploadDir: "etc"}
	if got := c.UploadDir(); got != "/srv/ingestor/etc" {
		t.Fatalf("UploadDir = %q, want /srv/ingestor/etc", got)
	}
	if got := c.UploadDirRelative(); got != "etc" {
		t.Fatalf("UploadDirRelative = %q, want etc", got)
	}

	root := &Config{root: "/srv/ingestor", uploadDir: "."}
	if got := root.UploadDir(); got != "/srv/ingestor" {
		t.Fatalf("UploadDir with '.' = %q, want /srv/ingestor", got)
	}

	// Simulate the admin setting /etc: it must resolve under root.
	c2 := &Config{root: "/srv/ingestor"}
	c2.uploadDir = c2.normalizeUploadDir("/etc")
	if got := c2.UploadDir(); got != "/srv/ingestor/etc" {
		t.Fatalf("UploadDir after /etc = %q, want /srv/ingestor/etc", got)
	}
}

func TestTrustProxyHeaders(t *testing.T) {
	t.Setenv("trust_proxy_headers", "")
	if (&Config{}).TrustProxyHeaders() {
		t.Fatal("empty env should default to false")
	}
	t.Setenv("trust_proxy_headers", "true")
	if !(&Config{}).TrustProxyHeaders() {
		t.Fatal("expected trust_proxy_headers=true to be honored")
	}
	t.Setenv("trust_proxy_headers", "TRUE")
	if !(&Config{}).TrustProxyHeaders() {
		t.Fatal("expected case-insensitive true to be honored")
	}
	t.Setenv("trust_proxy_headers", "false")
	if (&Config{}).TrustProxyHeaders() {
		t.Fatal("expected trust_proxy_headers=false to be rejected")
	}
}

func TestDurationEnv(t *testing.T) {
	if got := durationEnv("session_ttl", 24*time.Hour); got != 24*time.Hour {
		t.Fatalf("missing env should fall back, got %v", got)
	}
	t.Setenv("session_ttl", "2h")
	if got := durationEnv("session_ttl", 24*time.Hour); got != 2*time.Hour {
		t.Fatalf("got %v, want 2h", got)
	}
	t.Setenv("session_ttl", "junk")
	if got := durationEnv("session_ttl", 24*time.Hour); got != 24*time.Hour {
		t.Fatalf("invalid env should fall back, got %v", got)
	}
	t.Setenv("session_ttl", "0")
	if got := durationEnv("session_ttl", 24*time.Hour); got != 0 {
		t.Fatalf("0 should be honored (disable), got %v", got)
	}
}
