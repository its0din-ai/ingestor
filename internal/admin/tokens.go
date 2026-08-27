package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/encrypt0r/ingestor/internal/auth"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/web"
)

// ListTokens returns all bearer tokens for the Tokens view.
func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	tokens := h.cfg.BearerTokens()
	resp := make([]bearerTokenData, 0, len(tokens))
	for _, t := range tokens {
		resp = append(resp, tokenToData(t))
	}
	web.JSON(w, http.StatusOK, map[string]any{"tokens": resp})
}

// CreateToken generates a new random bearer token and persists it.
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
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

	bt := config.BearerToken{Token: randomToken(), Label: req.Label}
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

// DeleteToken removes a bearer token by its short id fingerprint.
func (h *Handler) DeleteToken(w http.ResponseWriter, r *http.Request) {
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
