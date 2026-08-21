package admin

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/auth"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/logging"
	"github.com/encrypt0r/ingestor/internal/ratelimit"
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
	if !h.loginLimiter.Allow(remote) {
		h.auditLog.LoginFailed(remote)
		web.JSON(w, http.StatusTooManyRequests, web.ErrorResponse{
			Status:  "error",
			Message: "too many login attempts, try again later",
		})
		return
	}
	password := r.FormValue("password")
	if !h.cfg.VerifyAdminPassword(password) {
		h.auditLog.LoginFailed(remote)
		csrf := auth.CSRFToken(r)
		h.render(w, r, "login", csrf, nil, "invalid password")
		return
	}
	if err := h.sessions.StartSession(w); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.auditLog.LoginSuccess(logging.ClientIP(r))
	http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	h.auditLog.Logout(logging.ClientIP(r))
	h.sessions.EndSession(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	csrf := auth.CSRFToken(r)
	history, _ := db.ListUploads(h.conn, 100, 0)
	h.render(w, r, "dashboard", csrf, history, "")
}

type dashboardData struct {
	View        string
	CSRF        string
	UploadDir   string
	MaxUploadMB int64
	BaseURL     string
	History     []db.UploadRecord
	Error       string
}

type bearerTokenData struct {
	Label     string `json:"label"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	TokenID   string `json:"token_id"`
}

type settingsData struct {
	UploadDir            string            `json:"upload_dir"`
	MaxUploadMB          int64             `json:"max_upload_mb"`
	QuarantineExtensions []string          `json:"quarantine_extensions"`
	BearerTokens         []bearerTokenData `json:"bearer_tokens"`
}

// SettingsJSON returns the current non-secret settings plus the bearer
// tokens (for the admin's own reference in the UI).
func (h *Handler) SettingsJSON(w http.ResponseWriter, r *http.Request) {
	tokens := make([]bearerTokenData, 0, len(h.cfg.BearerTokens()))
	for _, t := range h.cfg.BearerTokens() {
		data := bearerTokenData{
			Label:   t.Label,
			Token:   t.Token,
			TokenID: auth.TokenID(t.Token),
		}
		if !t.ExpiresAt.IsZero() {
			data.ExpiresAt = t.ExpiresAt.UTC().Format(time.RFC3339)
		}
		tokens = append(tokens, data)
	}
	data := settingsData{
		UploadDir:            h.cfg.UploadDir(),
		MaxUploadMB:          h.cfg.MaxUploadMB(),
		QuarantineExtensions: h.cfg.QuarantineExtensions(),
		BearerTokens:         tokens,
	}
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

	remote := logging.ClientIP(r)
	var changed []string

	if req.UploadDir != "" {
		if err := h.cfg.SetUploadDir(req.UploadDir); err != nil {
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
		h.auditLog.BearerChanged(remote)
	}
	if req.AdminPassword != "" {
		if !h.cfg.VerifyAdminPassword(req.CurrentPassword) {
			web.JSON(w, http.StatusUnauthorized, web.ErrorResponse{
				Status:  "error",
				Message: "current password is incorrect",
			})
			return
		}
		if err := h.cfg.SetAdminPassword(req.AdminPassword); err != nil {
			h.settingsErr(w, err)
			return
		}
		changed = append(changed, "admin_password")
		h.auditLog.PasswordChanged(remote)
		// Force every active session to re-authenticate.
		if err := db.DeleteAllSessions(h.conn); err != nil {
			slog.Warn("failed to invalidate sessions after password change", "err", err)
		}
	}

	if len(changed) > 0 {
		h.auditLog.SettingsChanged(remote, changed)
	}

	web.JSON(w, http.StatusOK, web.ErrorResponse{
		Status:  "ok",
		Message: "Settings saved",
	})
}

func (h *Handler) settingsErr(w http.ResponseWriter, err error) {
	web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
		Status:  "error",
		Message: "failed to save settings: " + err.Error(),
	})
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, view string, csrf string, history []db.UploadRecord, errMsg string) {
	data := dashboardData{
		View:        view,
		CSRF:        csrf,
		UploadDir:   h.cfg.UploadDir(),
		MaxUploadMB: h.cfg.MaxUploadMB(),
		BaseURL:     baseURL(r),
		History:     history,
		Error:       errMsg,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, data)
}

// baseURL derives the public base URL from the request as the browser sees
// it. Behind a reverse proxy the X-Forwarded-Proto / X-Forwarded-Host
// headers carry the external scheme and host, and the request's own Host is
// used otherwise. The configured listen address (cfg.Addr) is intentionally
// never used here: it is internal (e.g. 127.0.0.1:8081) and differs from the
// browser-facing URL.
func baseURL(r *http.Request) string {
	scheme := "http"
	if p := firstHeader(r, "X-Forwarded-Proto"); p != "" {
		scheme = p
	} else if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if h := firstHeader(r, "X-Forwarded-Host"); h != "" {
		host = h
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
