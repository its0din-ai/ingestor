package admin

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/auth"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/logging"
	"github.com/encrypt0r/ingestor/internal/web"
)

type Handler struct {
	cfg      *config.Config
	conn     *sql.DB
	tmpl     *template.Template
	auditLog *audit.Logger
}

func New(cfg *config.Config, conn *sql.DB, tmpl *template.Template, auditLog *audit.Logger) *Handler {
	return &Handler{cfg: cfg, conn: conn, tmpl: tmpl, auditLog: auditLog}
}

func (h *Handler) LoginForm(w http.ResponseWriter, r *http.Request) {
	csrf := auth.CSRFToken(r)
	h.render(w, "login", csrf, nil, "")
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	if !h.cfg.VerifyAdminPassword(password) {
		h.auditLog.LoginFailed(logging.ClientIP(r))
		csrf := auth.CSRFToken(r)
		h.render(w, "login", csrf, nil, "invalid password")
		return
	}
	if err := auth.StartSession(h.conn, w); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.auditLog.LoginSuccess(logging.ClientIP(r))
	http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	h.auditLog.Logout(logging.ClientIP(r))
	auth.EndSession(h.conn, r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	csrf := auth.CSRFToken(r)
	history, _ := db.ListUploads(h.conn, 100, 0)
	h.render(w, "dashboard", csrf, history, "")
}

type dashboardData struct {
	View        string
	CSRF        string
	UploadDir   string
	MaxUploadMB int64
	History     []db.UploadRecord
	Error       string
}

type settingsData struct {
	UploadDir            string   `json:"upload_dir"`
	MaxUploadMB          int64    `json:"max_upload_mb"`
	QuarantineExtensions []string `json:"quarantine_extensions"`
	BearerToken          string   `json:"bearer_token"`
}

// SettingsJSON returns the current non-secret settings plus the bearer token
// (for the admin's own reference in the UI).
func (h *Handler) SettingsJSON(w http.ResponseWriter, r *http.Request) {
	data := settingsData{
		UploadDir:            h.cfg.UploadDir(),
		MaxUploadMB:          h.cfg.MaxUploadMB(),
		QuarantineExtensions: h.cfg.QuarantineExtensions(),
		BearerToken:          h.cfg.BearerToken(),
	}
	web.JSON(w, http.StatusOK, data)
}

func (h *Handler) SaveSettingsJSON(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UploadDir            string   `json:"upload_dir"`
		MaxUploadMB          int64    `json:"max_upload_mb"`
		QuarantineExtensions []string `json:"quarantine_extensions"`
		BearerToken          string   `json:"bearer_token"`
		AdminPassword        string   `json:"admin_password"`
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
	if req.BearerToken != "" {
		if err := h.cfg.SetBearerToken(req.BearerToken); err != nil {
			h.settingsErr(w, err)
			return
		}
		changed = append(changed, "bearer_token")
		h.auditLog.BearerChanged(remote)
	}
	if req.AdminPassword != "" {
		if err := h.cfg.SetAdminPassword(req.AdminPassword); err != nil {
			h.settingsErr(w, err)
			return
		}
		changed = append(changed, "admin_password")
		h.auditLog.PasswordChanged(remote)
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

func (h *Handler) render(w http.ResponseWriter, view string, csrf string, history []db.UploadRecord, errMsg string) {
	data := dashboardData{
		View:        view,
		CSRF:        csrf,
		UploadDir:   h.cfg.UploadDir(),
		MaxUploadMB: h.cfg.MaxUploadMB(),
		History:     history,
		Error:       errMsg,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.Execute(w, data)
}
