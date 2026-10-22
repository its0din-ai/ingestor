package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/users"
	"github.com/encrypt0r/ingestor/internal/web"
)

type userData struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	QuotaMB     int64  `json:"quota_mb"`
	UsedBytes   int64  `json:"used_bytes"`
	Files       int64  `json:"files"`
	Disabled    bool   `json:"disabled"`
	CreatedAt   string `json:"created_at"`
	LastLoginAt string `json:"last_login_at"`
	TokenID     string `json:"token_id"`
}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	list, err := users.List(h.conn)
	if err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{Status: "error", Message: "failed to list users"})
		return
	}
	out := make([]userData, 0, len(list))
	for _, u := range list {
		used, files, _ := users.Usage(users.UserDir(h.cfg.UploadDir(), u.ID))
		d := userData{
			ID:        u.ID,
			Username:  u.Username,
			Role:      u.Role,
			QuotaMB:   u.QuotaMB,
			UsedBytes: used,
			Files:     files,
			Disabled:  u.Disabled,
			CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339),
		}
		if u.LastLoginAt.Valid {
			d.LastLoginAt = u.LastLoginAt.Time.UTC().Format(time.RFC3339)
		}
		if info, err := users.Token(h.conn, u.ID, h.tokenSecret()); err == nil {
			d.TokenID = info.TokenID
		}
		out = append(out, d)
	}
	web.JSON(w, http.StatusOK, map[string]any{"users": out})
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		QuotaMB  int64  `json:"quota_mb"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{Status: "error", Message: "invalid request body"})
		return
	}

	u, err := users.Create(h.conn, req.Username, req.Password, req.QuotaMB)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, users.ErrInvalidUsername), errors.Is(err, users.ErrWeakPassword), errors.Is(err, users.ErrInvalidQuota):
			status = http.StatusBadRequest
		case errors.Is(err, users.ErrUserExists):
			status = http.StatusConflict
		}
		web.JSON(w, status, web.ErrorResponse{Status: "error", Message: err.Error()})
		return
	}

	token, info, err := users.CreateToken(h.conn, u.ID, users.TokenLabel, h.tokenSecret())
	if err != nil {
		h.settingsErr(w, err)
		return
	}
	h.auditLog.UserCreated(r, u.Username, u.QuotaMB)

	web.JSON(w, http.StatusOK, map[string]any{
		"user": userData{
			ID:        u.ID,
			Username:  u.Username,
			Role:      u.Role,
			QuotaMB:   u.QuotaMB,
			CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339),
			TokenID:   info.TokenID,
		},
		"token": token,
	})
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       int64  `json:"id"`
		QuotaMB  *int64 `json:"quota_mb"`
		Disabled *bool  `json:"disabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{Status: "error", Message: "invalid request body"})
		return
	}
	target, err := h.regularUser(req.ID)
	if err != nil {
		h.userErr(w, err)
		return
	}

	var changed []string
	if req.QuotaMB != nil {
		if err := users.SetQuota(h.conn, target.ID, *req.QuotaMB); err != nil {
			h.userErr(w, err)
			return
		}
		changed = append(changed, "quota_mb")
	}
	if req.Disabled != nil {
		if err := users.SetDisabled(h.conn, target.ID, *req.Disabled); err != nil {
			h.userErr(w, err)
			return
		}
		changed = append(changed, "disabled")
	}
	if len(changed) == 0 {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{Status: "error", Message: "nothing to update"})
		return
	}

	h.auditLog.UserUpdated(r, target.Username, changed)
	web.JSON(w, http.StatusOK, web.ErrorResponse{Status: "ok", Message: "User updated"})
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         int64 `json:"id"`
		DeleteData bool  `json:"delete_data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{Status: "error", Message: "invalid request body"})
		return
	}
	if u, _ := identity.FromRequest(r); u.ID == req.ID {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{Status: "error", Message: "cannot delete your own account"})
		return
	}
	target, err := h.regularUser(req.ID)
	if err != nil {
		h.userErr(w, err)
		return
	}
	if err := users.Delete(h.conn, target.ID, h.cfg.UploadDir(), req.DeleteData); err != nil {
		h.userErr(w, err)
		return
	}
	h.auditLog.UserDeleted(r, target.Username, req.DeleteData)
	web.JSON(w, http.StatusOK, web.ErrorResponse{Status: "ok", Message: "User deleted"})
}

// UserFiles returns file metadata for a user's storage. Content is never
// served through this endpoint.
func (h *Handler) UserFiles(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
	if err != nil || id < 1 {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{Status: "error", Message: "invalid user_id"})
		return
	}
	target, err := h.regularUser(id)
	if err != nil {
		h.userErr(w, err)
		return
	}
	dir := users.UserDir(h.cfg.UploadDir(), target.ID)
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{Status: "error", Message: "failed to read storage"})
		return
	}

	files := make([]fileInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".ingestor-") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		files = append(files, fileInfo{
			Name:        e.Name(),
			Size:        info.Size(),
			Modified:    info.ModTime(),
			Quarantined: strings.HasSuffix(e.Name(), ".quarantined"),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Modified.After(files[j].Modified) })

	web.JSON(w, http.StatusOK, map[string]any{"files": files, "username": target.Username})
}

func (h *Handler) DeleteUserFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID int64  `json:"user_id"`
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{Status: "error", Message: "invalid request body"})
		return
	}
	target, err := h.regularUser(req.UserID)
	if err != nil {
		h.userErr(w, err)
		return
	}
	dir := users.UserDir(h.cfg.UploadDir(), target.ID)
	path, ok := resolveStoredPath(dir, req.Name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{Status: "error", Message: "invalid file name"})
		return
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			web.JSON(w, http.StatusNotFound, web.ErrorResponse{Status: "error", Message: "file not found"})
			return
		}
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{Status: "error", Message: "failed to delete file"})
		return
	}
	_ = db.DeleteUploadRecord(h.conn, target.ID, req.Name)
	_ = db.MarkPrivate(h.conn, target.ID, req.Name)
	h.auditLog.UserDataDeleted(r, target.Username)
	web.JSON(w, http.StatusOK, web.ErrorResponse{Status: "ok", Message: "File deleted"})
}

func (h *Handler) WipeUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID int64 `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{Status: "error", Message: "invalid request body"})
		return
	}
	target, err := h.regularUser(req.UserID)
	if err != nil {
		h.userErr(w, err)
		return
	}
	if err := users.WipeStorage(h.cfg.UploadDir(), target.ID); err != nil {
		h.userErr(w, err)
		return
	}
	if err := db.DeleteUserUploads(h.conn, target.ID); err != nil {
		h.userErr(w, err)
		return
	}
	h.auditLog.UserDataDeleted(r, target.Username)
	web.JSON(w, http.StatusOK, web.ErrorResponse{Status: "ok", Message: "User storage wiped"})
}

// regularUser resolves id to a non-superadmin account.
func (h *Handler) regularUser(id int64) (users.User, error) {
	u, err := users.Get(h.conn, id)
	if err != nil {
		return users.User{}, err
	}
	if u.Role != identity.RoleUser {
		return users.User{}, errNotRegularUser
	}
	return u, nil
}

var errNotRegularUser = errors.New("account is not a regular user")

func (h *Handler) userErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, users.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errNotRegularUser),
		errors.Is(err, users.ErrInvalidUsername),
		errors.Is(err, users.ErrWeakPassword),
		errors.Is(err, users.ErrInvalidQuota):
		status = http.StatusBadRequest
	}
	web.JSON(w, status, web.ErrorResponse{Status: "error", Message: err.Error()})
}
