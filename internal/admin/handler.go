package admin

import (
	"database/sql"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/auth"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/logging"
	"github.com/encrypt0r/ingestor/internal/ratelimit"
	"github.com/encrypt0r/ingestor/internal/users"
	"github.com/encrypt0r/ingestor/internal/version"
	"github.com/encrypt0r/ingestor/internal/web"
)

const (
	loginLimit  = 15
	loginWindow = 15 * time.Minute
)

type Handler struct {
	cfg          *config.Config
	conn         *sql.DB
	tmpl         *template.Template
	auditLog     *audit.Logger
	sessions     *auth.Manager
	loginLimiter *ratelimit.Limiter
}

func New(cfg *config.Config, conn *sql.DB, sessions *auth.Manager, tmpl *template.Template, auditLog *audit.Logger) *Handler {
	return &Handler{
		cfg:          cfg,
		conn:         conn,
		tmpl:         tmpl,
		auditLog:     auditLog,
		sessions:     sessions,
		loginLimiter: ratelimit.New(loginLimit, loginWindow),
	}
}

func (h *Handler) LoginForm(w http.ResponseWriter, r *http.Request) {
	csrf := auth.CSRFToken(r)
	h.render(w, r, "login", csrf, nil, "")
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	remote := logging.ClientIP(r)
	username := strings.TrimSpace(r.FormValue("username"))
	// Pre-multi-user .env files had no admin_username and the login form only
	// submitted a password. Keep those deployments working by resolving an
	// empty username to the single superadmin account.
	if username == "" && h.cfg.LegacyEnv() {
		if su, err := users.Superadmin(h.conn); err == nil {
			username = su.Username
		}
	}
	if !h.loginLimiter.Allow(remote) {
		h.auditLog.LoginFailed(r, username)
		web.JSON(w, http.StatusTooManyRequests, web.ErrorResponse{
			Status:  "error",
			Message: "too many login attempts, try again later",
		})
		return
	}
	u, err := users.Authenticate(h.conn, username, r.FormValue("password"))
	if err == nil && h.cfg.SingleUser() && u.Role != identity.RoleSuperadmin {
		// Multi-user accounts are ignored in single-user mode.
		err = users.ErrInvalidCredentials
	}
	if err != nil {
		h.auditLog.LoginFailed(r, username)
		csrf := auth.CSRFToken(r)
		h.render(w, r, "login", csrf, nil, "invalid username or password")
		return
	}
	if err := h.sessions.StartSession(w, u.ID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ctx := identity.WithUser(r.Context(), u)
	h.auditLog.LoginSuccess(r.WithContext(ctx), u.Username)
	http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	h.auditLog.Logout(r)
	h.sessions.EndSession(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	csrf := auth.CSRFToken(r)
	history, _ := db.ListUploads(h.conn, -1, 100, 0)
	h.render(w, r, "dashboard", csrf, history, "")
}

type dashboardData struct {
	View          string
	CSRF          string
	UploadDir     string
	MaxUploadMB   int64
	BaseURL       string
	History       []db.UploadRecord
	Error         string
	Role          string
	Username      string
	UserID        int64
	Version       string
	QuotaMB       int64
	UsedBytes     int64
	DefaultView   string
	AdminUsername string
	SingleUser    bool
}

type bearerTokenData struct {
	Label     string `json:"label"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	TokenID   string `json:"token_id"`
}

type settingsData struct {
	Username             string            `json:"username"`
	Role                 string            `json:"role"`
	QuotaMB              int64             `json:"quota_mb"`
	UsedBytes            int64             `json:"used_bytes"`
	UploadDir            string            `json:"upload_dir"`
	MaxUploadMB          int64             `json:"max_upload_mb"`
	QuarantineExtensions []string          `json:"quarantine_extensions"`
	BearerTokens         []bearerTokenData `json:"bearer_tokens"`
}

// SettingsJSON returns the current non-secret settings plus the bearer
// tokens (for the admin's own reference in the UI).
func (h *Handler) SettingsJSON(w http.ResponseWriter, r *http.Request) {
	u, _ := identity.FromRequest(r)
	data := settingsData{
		Username:  u.Username,
		Role:      u.Role,
		QuotaMB:   0,
		UsedBytes: 0,
	}
	if u.IsUser() {
		if rec, err := users.Get(h.conn, u.ID); err == nil {
			data.QuotaMB = rec.QuotaMB
		}
		data.UsedBytes, _, _ = users.Usage(users.UserDir(h.cfg.UploadDir(), u.ID))
		web.JSON(w, http.StatusOK, data)
		return
	}

	tokens := make([]bearerTokenData, 0, len(h.cfg.BearerTokens()))
	for _, t := range h.cfg.BearerTokens() {
		tok := bearerTokenData{
			Label:   t.Label,
			Token:   t.Token,
			TokenID: auth.TokenID(t.Token),
		}
		if !t.ExpiresAt.IsZero() {
			tok.ExpiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
		}
		tokens = append(tokens, tok)
	}
	data.UploadDir = h.cfg.UploadDirRelative()
	data.MaxUploadMB = h.cfg.MaxUploadMB()
	data.QuarantineExtensions = h.cfg.QuarantineExtensions()
	data.BearerTokens = tokens
	web.JSON(w, http.StatusOK, data)
}

func (h *Handler) SaveSettingsJSON(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UploadDir            string            `json:"upload_dir"`
		MaxUploadMB          int64             `json:"max_upload_mb"`
		QuarantineExtensions []string          `json:"quarantine_extensions"`
		BearerTokens         []bearerTokenData `json:"bearer_tokens"`
		CurrentPassword      string            `json:"current_password"`
		AdminPassword        string            `json:"admin_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid request body",
		})
		return
	}

	u, _ := identity.FromRequest(r)
	globalChange := req.UploadDir != "" || req.MaxUploadMB > 0 || req.QuarantineExtensions != nil || req.BearerTokens != nil
	if globalChange && !u.IsSuperadmin() {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{
			Status:  "error",
			Message: "only the superadmin can change global settings",
		})
		return
	}

	var changed []string

	if req.UploadDir != "" {
		if err := h.cfg.SetUploadDir(req.UploadDir); err != nil {
			if errors.Is(err, config.ErrInvalidUploadDir) {
				web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
					Status:  "error",
					Message: err.Error(),
				})
				return
			}
			h.settingsErr(w, err)
			return
		}
		changed = append(changed, "upload_dir")
	}
	if req.MaxUploadMB > 0 {
		if err := h.cfg.SetMaxUploadMB(req.MaxUploadMB); err != nil {
			h.settingsErr(w, err)
			return
		}
		changed = append(changed, "max_upload_mb")
	}
	if req.QuarantineExtensions != nil {
		if err := h.cfg.SetQuarantineExtensions(req.QuarantineExtensions); err != nil {
			h.settingsErr(w, err)
			return
		}
		changed = append(changed, "quarantine_extensions")
	}
	if req.BearerTokens != nil {
		tokens := make([]config.BearerToken, 0, len(req.BearerTokens))
		for _, t := range req.BearerTokens {
			bt := config.BearerToken{Token: t.Token, Label: t.Label}
			if t.Token == "" {
				continue
			}
			if t.ExpiresAt != "" {
				exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
				if err != nil {
					web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
						Status:  "error",
						Message: "invalid expiry: " + t.ExpiresAt,
					})
					return
				}
				bt.ExpiresAt = exp
			}
			tokens = append(tokens, bt)
		}
		if err := h.cfg.SetBearerTokens(tokens); err != nil {
			h.settingsErr(w, err)
			return
		}
		changed = append(changed, "bearer_tokens")
		h.auditLog.BearerChanged(r)
	}
	if req.AdminPassword != "" {
		if _, err := users.Authenticate(h.conn, u.Username, req.CurrentPassword); err != nil {
			web.JSON(w, http.StatusUnauthorized, web.ErrorResponse{
				Status:  "error",
				Message: "current password is incorrect",
			})
			return
		}
		if err := users.SetPassword(h.conn, u.ID, req.AdminPassword); err != nil {
			if errors.Is(err, users.ErrWeakPassword) {
				web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
					Status:  "error",
					Message: err.Error(),
				})
				return
			}
			h.settingsErr(w, err)
			return
		}
		changed = append(changed, "password")
		h.auditLog.PasswordChanged(r)
		// Force this account's active sessions to re-authenticate.
		if err := users.DeleteSessionsForUser(h.conn, u.ID); err != nil {
			slog.Warn("failed to invalidate sessions after password change", "err", err)
		}
	}

	if len(changed) > 0 {
		h.auditLog.SettingsChanged(r, changed)
	}

	web.JSON(w, http.StatusOK, web.ErrorResponse{
		Status:  "ok",
		Message: "Settings saved",
	})
}

// tokenSecret returns the key used to encrypt user API tokens at rest. Startup
// already validated it (config.Load), so an empty value cannot occur in a
// running server.
func (h *Handler) tokenSecret() []byte {
	secret, _ := h.cfg.JWTSecret()
	return secret
}

func (h *Handler) settingsErr(w http.ResponseWriter, err error) {
	web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
		Status:  "error",
		Message: "failed to save settings: " + err.Error(),
	})
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, view string, csrf string, history []db.UploadRecord, errMsg string) {
	data := dashboardData{
		View:          view,
		CSRF:          csrf,
		UploadDir:     h.cfg.UploadDir(),
		MaxUploadMB:   h.cfg.MaxUploadMB(),
		BaseURL:       baseURL(r),
		History:       history,
		Error:         errMsg,
		Version:       version.Version,
		DefaultView:   "files",
		AdminUsername: h.cfg.AdminUsername(),
		SingleUser:    h.cfg.SingleUser(),
	}
	if u, ok := identity.FromRequest(r); ok {
		data.Role = u.Role
		data.Username = u.Username
		data.UserID = u.ID
		if u.IsUser() {
			dir := users.UserDir(h.cfg.UploadDir(), u.ID)
			data.UploadDir = dir
			data.UsedBytes, _, _ = users.Usage(dir)
			if rec, err := users.Get(h.conn, u.ID); err == nil {
				data.QuotaMB = rec.QuotaMB
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, data)
}

// baseURL derives the public base URL from the request as the browser sees
// it. When the request is marked as arriving through a trusted reverse proxy
// (see logging.ProxyHeaders), X-Forwarded-Proto / X-Forwarded-Host carry the
// external scheme and host. Otherwise the request's own Host and TLS state are
// used. The configured listen address (cfg.Addr) is intentionally never used
// here: it is internal (e.g. 127.0.0.1:8081) and differs from the
// browser-facing URL.
func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if logging.TrustedProxy(r) {
		if p := firstHeader(r, "X-Forwarded-Proto"); p != "" {
			scheme = p
		}
		if h := firstHeader(r, "X-Forwarded-Host"); h != "" {
			host = h
		}
	}
	return scheme + "://" + host
}

func firstHeader(r *http.Request, name string) string {
	v := r.Header.Get(name)
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
