package audit

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/logging"
)

// Action is a machine-readable audit event type.
type Action string

const (
	ActionLoginFailed     Action = "login_failed"
	ActionLoginSuccess    Action = "login_success"
	ActionLogout          Action = "logout"
	ActionBearerFailed    Action = "bearer_failed"
	ActionUpload          Action = "upload"
	ActionDownload        Action = "download"
	ActionRead            Action = "read"
	ActionDelete          Action = "delete"
	ActionQuarantine      Action = "quarantine"
	ActionRelease         Action = "release"
	ActionMarkPublic      Action = "mark_public"
	ActionMarkPrivate     Action = "mark_private"
	ActionPublicOpen      Action = "public_open"
	ActionPublicDenied    Action = "public_denied"
	ActionSettingsChanged Action = "settings_changed"
	ActionPasswordChanged Action = "password_changed"
	ActionBearerChanged   Action = "bearer_changed"
)

type Logger struct {
	conn *sql.DB
}

func New(conn *sql.DB) *Logger {
	return &Logger{conn: conn}
}

// record stores an audit entry. The client IP and User-Agent are derived from
// the request so every entry carries consistent attribution. Actions received
// via the CF proxy (identified by its X-Morph-Real-Ip header) are marked in
// the summary so proxied traffic is easy to spot.
func (l *Logger) record(action Action, summary string, detail map[string]any, r *http.Request) {
	d := ""
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			d = string(b)
		}
	}
	remote, ua := "", ""
	if r != nil {
		remote = logging.ClientIP(r)
		ua = r.UserAgent()
		if logging.ViaMorphProxy(r) {
			summary += " via cf-proxy"
		}
	}
	_ = db.InsertAudit(l.conn, db.AuditRecord{
		Action:     string(action),
		Summary:    summary,
		Detail:     d,
		RemoteAddr: remote,
		UserAgent:  ua,
		CreatedAt:  time.Now(),
	})
}

func (l *Logger) LoginFailed(r *http.Request) {
	l.record(ActionLoginFailed, "failed admin login attempt", nil, r)
}

func (l *Logger) LoginSuccess(r *http.Request) {
	l.record(ActionLoginSuccess, "admin logged in", nil, r)
}

func (l *Logger) Logout(r *http.Request) {
	l.record(ActionLogout, "admin logged out", nil, r)
}

func (l *Logger) BearerFailed(r *http.Request, path string) {
	l.record(ActionBearerFailed, "failed bearer authentication", map[string]any{"path": path}, r)
}

func (l *Logger) Upload(r *http.Request, originalName, storedName string, size int64, quarantined bool, tokenID, tokenLabel string) {
	summary := "file uploaded: " + originalName
	if tokenID != "" || tokenLabel != "" {
		// Prefer the configured label for attribution; fall back to the
		// token's short id fingerprint when no label is set.
		if tokenLabel != "" {
			summary = "bearer token " + tokenLabel + " used for upload: " + originalName
		} else {
			summary = "bearer token id " + tokenID + " used for upload: " + originalName
		}
	}
	detail := map[string]any{
		"original_name": originalName,
		"stored_name":   storedName,
		"size":          size,
		"quarantined":   quarantined,
	}
	if tokenID != "" {
		detail["token_id"] = tokenID
	}
	if tokenLabel != "" {
		detail["token_label"] = tokenLabel
	}
	l.record(ActionUpload, summary, detail, r)
}

func (l *Logger) Download(r *http.Request, name string) {
	l.record(ActionDownload, "file downloaded: "+name, map[string]any{"stored_name": name}, r)
}

func (l *Logger) Read(r *http.Request, name string) {
	l.record(ActionRead, "file read: "+name, map[string]any{"stored_name": name}, r)
}

func (l *Logger) Delete(r *http.Request, name string) {
	l.record(ActionDelete, "file deleted: "+name, map[string]any{"stored_name": name}, r)
}

func (l *Logger) Quarantine(r *http.Request, name string) {
	l.record(ActionQuarantine, "file quarantined: "+name, map[string]any{"stored_name": name}, r)
}

func (l *Logger) Release(r *http.Request, name string) {
	l.record(ActionRelease, "file released from quarantine: "+name, map[string]any{"stored_name": name}, r)
}

func (l *Logger) MarkPublic(r *http.Request, name string) {
	l.record(ActionMarkPublic, "file marked public: "+name, map[string]any{"stored_name": name}, r)
}

func (l *Logger) MarkPrivate(r *http.Request, name string) {
	l.record(ActionMarkPrivate, "file made private: "+name, map[string]any{"stored_name": name}, r)
}

func (l *Logger) PublicOpen(r *http.Request, name string) {
	l.record(ActionPublicOpen, "public file opened: "+name, map[string]any{"stored_name": name}, r)
}

func (l *Logger) PublicDenied(r *http.Request, name, reason string) {
	l.record(ActionPublicDenied, "public file access denied: "+name, map[string]any{"stored_name": name, "reason": reason}, r)
}

func (l *Logger) SettingsChanged(r *http.Request, fields []string) {
	l.record(ActionSettingsChanged, "settings updated", map[string]any{"fields": fields}, r)
}

func (l *Logger) PasswordChanged(r *http.Request) {
	l.record(ActionPasswordChanged, "admin password changed", nil, r)
}

func (l *Logger) BearerChanged(r *http.Request) {
	l.record(ActionBearerChanged, "bearer token changed", nil, r)
}
