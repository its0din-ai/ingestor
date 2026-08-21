package audit

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/encrypt0r/ingestor/internal/db"
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

func (l *Logger) record(action Action, summary string, detail map[string]any, remote string) {
	d := ""
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			d = string(b)
		}
	}
	_ = db.InsertAudit(l.conn, db.AuditRecord{
		Action:     string(action),
		Summary:    summary,
		Detail:     d,
		RemoteAddr: remote,
		CreatedAt:  time.Now(),
	})
}

func (l *Logger) LoginFailed(remote string) {
	l.record(ActionLoginFailed, "failed admin login attempt", nil, remote)
}

func (l *Logger) LoginSuccess(remote string) {
	l.record(ActionLoginSuccess, "admin logged in", nil, remote)
}

func (l *Logger) Logout(remote string) {
	l.record(ActionLogout, "admin logged out", nil, remote)
}

func (l *Logger) BearerFailed(remote, path string) {
	l.record(ActionBearerFailed, "failed bearer authentication", map[string]any{"path": path}, remote)
}

func (l *Logger) Upload(remote, originalName, storedName string, size int64, quarantined bool) {
	l.record(ActionUpload, "file uploaded: "+originalName, map[string]any{
		"original_name": originalName,
		"stored_name":   storedName,
		"size":          size,
		"quarantined":   quarantined,
	}, remote)
}

func (l *Logger) Download(remote, name string) {
	l.record(ActionDownload, "file downloaded: "+name, map[string]any{"stored_name": name}, remote)
}

func (l *Logger) Read(remote, name string) {
	l.record(ActionRead, "file read: "+name, map[string]any{"stored_name": name}, remote)
}

func (l *Logger) Delete(remote, name string) {
	l.record(ActionDelete, "file deleted: "+name, map[string]any{"stored_name": name}, remote)
}

func (l *Logger) Quarantine(remote, name string) {
	l.record(ActionQuarantine, "file quarantined: "+name, map[string]any{"stored_name": name}, remote)
}

func (l *Logger) Release(remote, name string) {
	l.record(ActionRelease, "file released from quarantine: "+name, map[string]any{"stored_name": name}, remote)
}

func (l *Logger) SettingsChanged(remote string, fields []string) {
	l.record(ActionSettingsChanged, "settings updated", map[string]any{"fields": fields}, remote)
}

func (l *Logger) PasswordChanged(remote string) {
	l.record(ActionPasswordChanged, "admin password changed", nil, remote)
}

func (l *Logger) BearerChanged(remote string) {
	l.record(ActionBearerChanged, "bearer token changed", nil, remote)
}
