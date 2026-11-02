package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/encrypt0r/ingestor/internal/auth"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/mnemonic"
	"github.com/encrypt0r/ingestor/internal/users"
	"github.com/encrypt0r/ingestor/internal/web"
)

const (
	// maxTokenAllocAttempts bounds the silent retry loop when a generated
	// phrase is already in use. A collision in a 7776^4 space is vanishingly
	// rare, so this is only a safety bound.
	maxTokenAllocAttempts = 20
)

// newMnemonic is a seam so tests can force a collision.
var newMnemonic = mnemonic.Generate

// ListTokens returns the account's own token metadata for regular users, or
// the legacy .env token list for the superadmin.
func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	u, _ := identity.FromRequest(r)
	if u.IsUser() {
		info, err := users.Token(h.conn, u.ID, h.tokenSecret())
		if err != nil {
			web.JSON(w, http.StatusOK, map[string]any{"tokens": []bearerTokenData{}, "user_token": true})
			return
		}
		web.JSON(w, http.StatusOK, map[string]any{
			"tokens": []bearerTokenData{{
				Label:     info.Label,
				TokenID:   info.TokenID,
				ExpiresAt: "",
				Token:     info.Token,
			}},
			"user_token": true,
			"created_at": info.CreatedAt.UTC().Format(time.RFC3339),
		})
		return
	}

	tokens := h.cfg.BearerTokens()
	resp := make([]bearerTokenData, 0, len(tokens))
	for _, t := range tokens {
		resp = append(resp, tokenToData(t))
	}
	web.JSON(w, http.StatusOK, map[string]any{"tokens": resp})
}

// RotateToken replaces the signed-in user's API token and returns the new
// plaintext once.
func (h *Handler) RotateToken(w http.ResponseWriter, r *http.Request) {
	u, _ := identity.FromRequest(r)
	if !u.IsUser() {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{
			Status:  "error",
			Message: "only regular users have API tokens",
		})
		return
	}
	token, info, err := users.RotateToken(h.conn, u.ID, users.TokenLabel, h.tokenSecret())
	if err != nil {
		h.settingsErr(w, err)
		return
	}
	h.auditLog.UserTokenRotated(r, u.Username)
	web.JSON(w, http.StatusOK, map[string]any{
		"token":    token,
		"token_id": info.TokenID,
		"label":    info.Label,
	})
}

// CreateToken generates a new random legacy bearer token and persists it.
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	if u, _ := identity.FromRequest(r); !u.IsSuperadmin() {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{
			Status:  "error",
			Message: "superadmin access required",
		})
		return
	}
	var req struct {
		Label     string `json:"label"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid request body",
		})
		return
	}

	bt := config.BearerToken{Token: randomToken(), Label: strings.TrimSpace(req.Label)}
	if !validTokenLabel(bt.Label) {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "label may not contain commas, pipes, or equals signs",
		})
		return
	}
	if req.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
				Status:  "error",
				Message: "invalid expiry: " + req.ExpiresAt,
			})
			return
		}
		bt.ExpiresAt = exp
	}

	tokens := h.cfg.BearerTokens()
	tokens = append(tokens, bt)
	if err := h.cfg.SetBearerTokens(tokens); err != nil {
		h.settingsErr(w, err)
		return
	}

	h.auditLog.BearerChanged(r)
	web.JSON(w, http.StatusOK, map[string]any{"token": tokenToData(bt)})
}

// CreatePlainToken adds a workspace bearer token whose value is a freshly
// generated five-word mnemonic (for example
// "amber-cobalt-lunar-otter-violet"). The phrase is unique across personal and
// workspace tokens; collisions are retried silently and never reported, so
// allocation is not an oracle.
func (h *Handler) CreatePlainToken(w http.ResponseWriter, r *http.Request) {
	u, _ := identity.FromRequest(r)
	if !u.IsSuperadmin() {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{
			Status:  "error",
			Message: "superadmin access required",
		})
		return
	}
	var req struct {
		Label     string `json:"label"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid request body",
		})
		return
	}

	label := strings.TrimSpace(req.Label)
	if !validTokenLabel(label) {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "label may not contain commas, pipes, or equals signs",
		})
		return
	}

	token, err := h.allocatePlainToken()
	if err != nil {
		h.settingsErr(w, err)
		return
	}

	bt := config.BearerToken{Token: token, Label: label}
	if req.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
				Status:  "error",
				Message: "invalid expiry: " + req.ExpiresAt,
			})
			return
		}
		bt.ExpiresAt = exp
	}

	tokens := h.cfg.BearerTokens()
	tokens = append(tokens, bt)
	if err := h.cfg.SetBearerTokens(tokens); err != nil {
		h.settingsErr(w, err)
		return
	}

	h.auditLog.BearerChanged(r)
	web.JSON(w, http.StatusOK, map[string]any{"token": tokenToData(bt)})
}

// CreatePlainUserToken replaces a regular user's personal API token with a
// freshly generated five-word mnemonic. The value is hashed for lookup and
// encrypted at rest so the owner can still view it; it replaces the previous
// personal token exactly like RotateToken does.
func (h *Handler) CreatePlainUserToken(w http.ResponseWriter, r *http.Request) {
	u, ok := identity.FromRequest(r)
	if !ok || !u.IsUser() {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{
			Status:  "error",
			Message: "only regular users have personal API tokens",
		})
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid request body",
		})
		return
	}
	label := strings.TrimSpace(req.Label)
	if !validTokenLabel(label) {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "label may not contain commas, pipes, or equals signs",
		})
		return
	}

	info, err := h.replaceUserPlainToken(u.ID, label)
	if err != nil {
		h.settingsErr(w, err)
		return
	}
	h.auditLog.UserTokenPlain(r, u.Username)
	web.JSON(w, http.StatusOK, map[string]any{
		"token":    info.Token,
		"token_id": info.TokenID,
		"label":    info.Label,
	})
}

// replaceUserPlainToken allocates an unused mnemonic and stores it for userID.
// It retries if a concurrent insert claims the same value; the failed insert
// transaction rolls back, so the user's previous token remains intact.
func (h *Handler) replaceUserPlainToken(userID int64, label string) (users.TokenInfo, error) {
	for i := 0; i < maxTokenAllocAttempts; i++ {
		value, err := h.allocatePlainToken()
		if err != nil {
			return users.TokenInfo{}, err
		}
		info, err := users.CreateTokenValue(h.conn, userID, label, value, h.tokenSecret())
		if err == nil {
			return info, nil
		}
		if _, taken := users.TokenOwner(h.conn, value); taken {
			continue
		}
		return users.TokenInfo{}, err
	}
	return users.TokenInfo{}, errors.New("could not allocate an unused token")
}

// allocatePlainToken returns a generated phrase that is not used by any
// personal or workspace token. Collisions are redrawn silently; the caller is
// never told that a particular phrase was taken.
func (h *Handler) allocatePlainToken() (string, error) {
	for i := 0; i < maxTokenAllocAttempts; i++ {
		value, err := newMnemonic()
		if err != nil {
			return "", err
		}
		if _, taken := users.TokenOwner(h.conn, value); taken {
			continue
		}
		if h.workspaceTokenTaken(value) {
			continue
		}
		return value, nil
	}
	return "", errors.New("could not allocate an unused token")
}

// workspaceTokenTaken reports whether the workspace list already uses value.
func (h *Handler) workspaceTokenTaken(value string) bool {
	for _, t := range h.cfg.BearerTokens() {
		if t.Token == value {
			return true
		}
	}
	return false
}

// validTokenLabel reports whether label can be serialized next to a token.
func validTokenLabel(label string) bool {
	return !strings.ContainsAny(label, ",|=")
}

// DeleteToken removes a bearer token by its short id fingerprint.
func (h *Handler) DeleteToken(w http.ResponseWriter, r *http.Request) {
	if u, _ := identity.FromRequest(r); !u.IsSuperadmin() {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{
			Status:  "error",
			Message: "superadmin access required",
		})
		return
	}
	tokenID := r.FormValue("token_id")
	if tokenID == "" {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "token_id is required",
		})
		return
	}

	tokens := h.cfg.BearerTokens()
	out := tokens[:0]
	found := false
	for _, t := range tokens {
		if auth.TokenID(t.Token) == tokenID {
			found = true
			continue
		}
		out = append(out, t)
	}
	if !found {
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "token not found",
		})
		return
	}
	if err := h.cfg.SetBearerTokens(out); err != nil {
		h.settingsErr(w, err)
		return
	}

	h.auditLog.BearerChanged(r)
	web.JSON(w, http.StatusOK, web.ErrorResponse{Status: "ok", Message: "Token deleted"})
}

func tokenToData(t config.BearerToken) bearerTokenData {
	d := bearerTokenData{
		Label:   t.Label,
		Token:   t.Token,
		TokenID: auth.TokenID(t.Token),
	}
	if !t.ExpiresAt.IsZero() {
		d.ExpiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return d
}

// randomToken returns a 64-character hex token (32 random bytes).
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
