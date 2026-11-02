package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/mnemonic"
	"github.com/encrypt0r/ingestor/internal/users"
)

type plainTokenReq struct {
	Label     string `json:"label,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

func postPlainToken(t *testing.T, h *Handler, u identity.User, req plainTokenReq) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/dashboard/api/tokens/plain", strings.NewReader(string(body)))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = withUser(httpReq, u)
	rec := httptest.NewRecorder()
	h.CreatePlainToken(rec, httpReq)
	return rec
}

func postPlainUserToken(t *testing.T, h *Handler, u identity.User, req plainTokenReq) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/dashboard/api/user-token/plain", strings.NewReader(string(body)))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = withUser(httpReq, u)
	rec := httptest.NewRecorder()
	h.CreatePlainUserToken(rec, httpReq)
	return rec
}

func assertMnemonic(t *testing.T, token string) {
	t.Helper()
	parts := strings.Split(token, "-")
	if len(parts) != mnemonic.WordCount {
		t.Fatalf("token %q has %d words, want %d", token, len(parts), mnemonic.WordCount)
	}
	for _, p := range parts {
		if p == "" {
			t.Fatalf("token %q has an empty word", token)
		}
		for _, r := range p {
			if r < 'a' || r > 'z' {
				t.Fatalf("token %q contains non-lowercase-letter %q", token, r)
			}
		}
	}
}

func TestCreatePlainToken(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)

	rec := postPlainToken(t, h, su, plainTokenReq{Label: "laptop", ExpiresAt: "2027-06-01T00:00:00Z"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token bearerTokenData `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	assertMnemonic(t, resp.Token.Token)
	if resp.Token.Label != "laptop" {
		t.Fatalf("label = %q, want laptop", resp.Token.Label)
	}

	got, ok := h.cfg.AuthenticateBearer(resp.Token.Token)
	if !ok {
		t.Fatal("generated token does not authenticate")
	}
	if got.Label != "laptop" || got.ExpiresAt.IsZero() {
		t.Fatalf("stored token = %+v", got)
	}
	if n := len(h.cfg.BearerTokens()); n != 1 {
		t.Fatalf("stored %d tokens, want 1", n)
	}
}

func TestCreatePlainTokenRetriesSilently(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)

	const taken = "amber-cobalt-lunar-otter-violet"
	const fresh = "brisk-harbor-velvet-walnut-ember"
	if err := h.cfg.SetBearerTokens([]config.BearerToken{{Token: taken}}); err != nil {
		t.Fatal(err)
	}

	restore := swapMnemonic(taken, fresh)
	defer restore()

	rec := postPlainToken(t, h, su, plainTokenReq{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token bearerTokenData `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token.Token != fresh {
		t.Fatalf("generated token = %q, want the redrawn value %q", resp.Token.Token, fresh)
	}
	if !h.workspaceTokenTaken(taken) {
		t.Fatal("pre-existing workspace token was disturbed")
	}
	// A collision is never reported to the caller.
	if strings.Contains(strings.ToLower(rec.Body.String()), "already") {
		t.Fatalf("response leaks the collision: %s", rec.Body.String())
	}
}

func TestCreatePlainUserToken(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}

	oldToken, _, err := users.CreateToken(conn, alice.ID, "api", h.tokenSecret())
	if err != nil {
		t.Fatal(err)
	}

	rec := postPlainUserToken(t, h, u, plainTokenReq{Label: "laptop"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token   string `json:"token"`
		TokenID string `json:"token_id"`
		Label   string `json:"label"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	assertMnemonic(t, resp.Token)

	owner, ok := users.AuthenticateToken(conn, resp.Token)
	if !ok || owner.ID != alice.ID {
		t.Fatalf("token owner = %+v, ok = %v", owner, ok)
	}
	if _, ok := users.AuthenticateToken(conn, oldToken); ok {
		t.Fatal("previous token still authenticates after replacement")
	}
	info, err := users.Token(conn, alice.ID, h.tokenSecret())
	if err != nil {
		t.Fatal(err)
	}
	if info.Token != resp.Token || info.Label != "laptop" {
		t.Fatalf("stored token = %+v", info)
	}
}

func TestCreatePlainUserTokenRetriesSilently(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := users.Create(conn, "bob", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	aliceID := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}

	const taken = "amber-cobalt-lunar-otter-violet"
	const fresh = "brisk-harbor-velvet-walnut-ember"
	if _, err := users.CreateTokenValue(conn, bob.ID, "", taken, h.tokenSecret()); err != nil {
		t.Fatal(err)
	}

	restore := swapMnemonic(taken, fresh)
	defer restore()

	rec := postPlainUserToken(t, h, aliceID, plainTokenReq{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token != fresh {
		t.Fatalf("generated token = %q, want %q", resp.Token, fresh)
	}
	if owner, ok := users.AuthenticateToken(conn, taken); !ok || owner.ID != bob.ID {
		t.Fatal("bob's token was disturbed by alice's retry")
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "already") {
		t.Fatalf("response leaks the collision: %s", rec.Body.String())
	}
}

func TestCreatePlainTokenRejectsBadLabel(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)

	rec := postPlainToken(t, h, su, plainTokenReq{Label: "bad,label"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if n := len(h.cfg.BearerTokens()); n != 0 {
		t.Fatalf("rejected request stored %d token(s)", n)
	}
}

func TestCreatePlainUserTokenRejectsBadLabel(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}

	rec := postPlainUserToken(t, h, u, plainTokenReq{Label: "bad|label"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
	if _, err := users.Token(conn, alice.ID, h.tokenSecret()); err == nil {
		t.Fatal("rejected request created a token")
	}
}

func TestCreatePlainTokenRequiresSuperadmin(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}

	rec := postPlainToken(t, h, u, plainTokenReq{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
}

func TestCreatePlainUserTokenRequiresRegularUser(t *testing.T) {
	h, conn := testHandler(t)
	su := superadmin(t, conn)

	rec := postPlainUserToken(t, h, su, plainTokenReq{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
}

// swapMnemonic replaces the generator for one test: the first draw returns
// taken, later draws return fresh. The restore function must be deferred.
func swapMnemonic(taken, fresh string) func() {
	original := newMnemonic
	calls := 0
	newMnemonic = func() (string, error) {
		calls++
		if calls == 1 {
			return taken, nil
		}
		return fresh, nil
	}
	return func() { newMnemonic = original }
}
