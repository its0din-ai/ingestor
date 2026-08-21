package admin

import (
	"strings"
	"testing"
	"time"

	"github.com/encrypt0r/ingestor/internal/config"
)

func TestRandomToken(t *testing.T) {
	tok := randomToken()
	if len(tok) != 64 {
		t.Fatalf("randomToken length = %d, want 64", len(tok))
	}
	for _, c := range tok {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("randomToken contains non-hex char %q", c)
		}
	}
	tok2 := randomToken()
	if tok == tok2 {
		t.Fatal("two random tokens must differ")
	}
}

func TestTokenToData(t *testing.T) {
	exp := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	d := tokenToData(config.BearerToken{Token: "abc", Label: "bob", ExpiresAt: exp})
	if d.Token != "abc" || d.Label != "bob" || d.ExpiresAt != "2027-06-01T00:00:00Z" {
		t.Fatalf("unexpected data: %+v", d)
	}
	if len(d.TokenID) != 6 {
		t.Fatalf("TokenID length = %d, want 6", len(d.TokenID))
	}

	indef := tokenToData(config.BearerToken{Token: "xyz"})
	if indef.ExpiresAt != "" {
		t.Fatalf("no-expiry token should have empty expires_at, got %q", indef.ExpiresAt)
	}
}
