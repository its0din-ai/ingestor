package admin

import (
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/diskusage"
	"github.com/encrypt0r/ingestor/internal/filetype"
	"github.com/encrypt0r/ingestor/internal/web"
)

type fileInfo struct {
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	Modified    time.Time `json:"modified"`
	Quarantined bool      `json:"quarantined"`
	UploaderIP  string    `json:"uploader_ip"`
	Readable    bool      `json:"readable"`
	Public      bool      `json:"public"`
}

// DiskUsage reports storage consumed by the upload directory plus the
// filesystem totals, so the dashboard can show a disk monitor.
func (h *Handler) DiskUsage(w http.ResponseWriter, r *http.Request) {
	info, err := diskusage.Summary(h.cfg.UploadDir())
	if err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to read disk usage",
		})
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{
		"upload_dir_bytes": info.UploadDirBytes,
		"used_bytes":       info.UsedBytes,
		"total_bytes":      info.TotalBytes,
		"free_bytes":       info.FreeBytes,
		"free_percent":     math.Round(diskusage.FreePercent(info)*10) / 10,
	})
}

// ListFiles returns the files currently stored in the upload directory.
func (h *Handler) ListFiles(w http.ResponseWriter, r *http.Request) {
	dir := h.cfg.UploadDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to read upload directory",
		})
		return
	}

	files := make([]fileInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		// Skip symbolic links: access handlers refuse them, and they must not
		// appear in the listing either (potential LFI redirect).
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		ip, _ := db.UploaderIP(h.conn, e.Name())
		readable, _ := filetype.IsText(filepath.Join(dir, e.Name()))
		files = append(files, fileInfo{
			Name:        e.Name(),
			Size:        info.Size(),
			Modified:    info.ModTime(),
			Quarantined: strings.HasSuffix(e.Name(), ".quarantined"),
			UploaderIP:  ip,
			Readable:    readable,
			Public:      db.IsPublic(h.conn, e.Name()),
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Modified.After(files[j].Modified)
	})

	web.JSON(w, http.StatusOK, map[string]any{"files": files})
}

// storedPath validates name as a single path component inside the upload
// directory, preventing traversal, LFI, and header injection. It returns the
// resolved path and whether the name was acceptable.
func (h *Handler) storedPath(name string) (string, bool) {
	return resolveStoredPath(h.cfg.UploadDir(), name)
}

// resolveStoredPath performs the actual validation so it can be unit tested.
// Stored files always have a single-component name, so any input containing
// a path separator, parent references, or control bytes is rejected outright
// (no normalization tricks, no dot-segment collapsing). The resolved path
// must also stay inside the upload directory.
func resolveStoredPath(dir, name string) (string, bool) {
	if dir == "" {
		return "", false
	}
	// Windows-style separators are treated as hostile input and rejected.
	name = strings.ReplaceAll(name, "\\", "/")
	if name == "" || strings.Contains(name, "/") {
		return "", false
	}
	if name == "." || name == ".." {
		return "", false
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return "", false
		}
	}

	dirClean := filepath.Clean(dir)
	absDir, err := filepath.Abs(dirClean)
	if err != nil {
		return "", false
	}
	path := filepath.Join(dirClean, name)
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", false
	}
	if absPath != absDir && !strings.HasPrefix(absPath, absDir+string(os.PathSeparator)) {
		return "", false
	}
	return path, true
}

// headerFilename returns a name that is safe to embed in a Content-Disposition
// header value (no quotes, backslashes, or control characters).
func headerFilename(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
}

// Download serves a stored file.
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	path, ok := h.storedPath(r.URL.Query().Get("name"))
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	if !h.fileExists(path) {
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}

	name := filepath.Base(path)
	w.Header().Set("Content-Disposition", "attachment; filename=\""+headerFilename(name)+"\"")
	h.auditLog.Download(r, name)
	http.ServeFile(w, r, path)
}

// Read serves a stored text file inline as text/plain so it can be viewed
// directly in the browser. Binary files are rejected; content is always
// served as text/plain and never rendered as HTML.
func (h *Handler) Read(w http.ResponseWriter, r *http.Request) {
	path, ok := h.storedPath(r.URL.Query().Get("name"))
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	if !h.fileExists(path) {
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}

	text, err := filetype.IsText(path)
	if err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to read file",
		})
		return
	}
	if !text {
		web.JSON(w, http.StatusUnsupportedMediaType, web.ErrorResponse{
			Status:  "error",
			Message: "binary files cannot be viewed in the browser",
		})
		return
	}

	name := filepath.Base(path)
	h.auditLog.Read(r, name)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=\""+headerFilename(name)+"\"")
	http.ServeFile(w, r, path)
}

// Quarantine renames a stored file to append the .quarantined suffix so it
// cannot be executed or served as its original type.
func (h *Handler) Quarantine(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	path, ok := h.storedPath(name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}
	if strings.HasSuffix(name, ".quarantined") {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "file is already quarantined",
		})
		return
	}
	if !h.fileExists(path) {
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}

	target := path + ".quarantined"
	if _, err := os.Stat(target); err == nil {
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "a quarantined file with that name already exists",
		})
		return
	}
	if err := os.Rename(path, target); err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to quarantine file",
		})
		return
	}

	_ = db.SetUploadQuarantined(h.conn, name, true)
	if db.IsPublic(h.conn, name) {
		_ = db.MarkPrivate(h.conn, name)
	}
	h.auditLog.Quarantine(r, name)

	web.JSON(w, http.StatusOK, web.ErrorResponse{
		Status:  "ok",
		Message: "File quarantined",
	})
}

// Release removes the .quarantined suffix from a stored file.
func (h *Handler) Release(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if !strings.HasSuffix(name, ".quarantined") {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "file is not quarantined",
		})
		return
	}
	path, ok := h.storedPath(name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}
	if !h.fileExists(path) {
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}

	base := strings.TrimSuffix(name, ".quarantined")
	basePath, ok := h.storedPath(base)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}
	if _, err := os.Stat(basePath); err == nil {
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "the original file name is already taken",
		})
		return
	}
	if err := os.Rename(path, basePath); err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to release file",
		})
		return
	}

	_ = db.SetUploadQuarantined(h.conn, base, false)
	h.auditLog.Release(r, base)

	web.JSON(w, http.StatusOK, web.ErrorResponse{
		Status:  "ok",
		Message: "File released from quarantine",
	})
}

// fileExists reports whether path is a regular (non-symlink) file. Symlinks
// are rejected so a compromised upload directory cannot redirect reads to
// arbitrary files on disk.
func (h *Handler) fileExists(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return true
}

// MarkPublic registers a stored file for anonymous access via /pub.
func (h *Handler) MarkPublic(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	path, ok := h.storedPath(name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}
	if !h.fileExists(path) {
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}
	if strings.HasSuffix(name, ".quarantined") {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "quarantined files cannot be shared publicly",
		})
		return
	}

	if err := db.MarkPublic(h.conn, name); err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to mark file public",
		})
		return
	}
	h.auditLog.MarkPublic(r, name)

	web.JSON(w, http.StatusOK, web.ErrorResponse{Status: "ok", Message: "File is now public"})
}

// MarkPrivate revokes anonymous access for a stored file.
func (h *Handler) MarkPrivate(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	path, ok := h.storedPath(name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}
	if !h.fileExists(path) {
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}

	if err := db.MarkPrivate(h.conn, name); err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to make file private",
		})
		return
	}
	h.auditLog.MarkPrivate(r, name)

	web.JSON(w, http.StatusOK, web.ErrorResponse{Status: "ok", Message: "File is now private"})
}

// PublicFile serves a publicly shared file without authentication. Files not
// marked public (or quarantined) are indistinguishable from missing files.
// Every access attempt — successful or denied — is written to the audit log.
func (h *Handler) PublicFile(w http.ResponseWriter, r *http.Request) {
	requested := r.URL.Query().Get("name")
	path, ok := h.storedPath(requested)
	if !ok {
		h.auditLog.PublicDenied(r, requested, "invalid_name")
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not available",
		})
		return
	}
	if !h.fileExists(path) {
		name := filepath.Base(path)
		h.auditLog.PublicDenied(r, name, "not_found")
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not available",
		})
		return
	}

	name := filepath.Base(path)
	if strings.HasSuffix(name, ".quarantined") || !db.IsPublic(h.conn, name) {
		reason := "not_public"
		if strings.HasSuffix(name, ".quarantined") {
			reason = "quarantined"
		}
		h.auditLog.PublicDenied(r, name, reason)
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not available",
		})
		return
	}

	h.auditLog.PublicOpen(r, name)

	// Text files are served inline as text/plain for reading; everything else
	// is an attachment download.
	if text, _ := filetype.IsText(path); text {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "inline; filename=\""+headerFilename(name)+"\"")
	} else {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+headerFilename(name)+"\"")
	}
	http.ServeFile(w, r, path)
}

// Delete removes a stored file.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	path, ok := h.storedPath(r.FormValue("name"))
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	if !h.fileExists(path) {
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}

	if err := os.Remove(path); err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to delete file",
		})
		return
	}

	h.auditLog.Delete(r, filepath.Base(path))

	web.JSON(w, http.StatusOK, web.ErrorResponse{
		Status:  "ok",
		Message: "File deleted",
	})
}

// ListAudit returns a paginated audit log (10 rows per page).
func (h *Handler) ListAudit(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const perPage = 10

	total, err := db.CountAudit(h.conn)
	if err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to count audit log",
		})
		return
	}

	rows, err := db.ListAudit(h.conn, perPage, (page-1)*perPage)
	if err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to read audit log",
		})
		return
	}

	type auditEntry struct {
		ID         int64  `json:"id"`
		Action     string `json:"action"`
		Summary    string `json:"summary"`
		Detail     string `json:"detail"`
		RemoteAddr string `json:"remote_addr"`
		UserAgent  string `json:"user_agent"`
		CreatedAt  string `json:"created_at"`
	}

	entries := make([]auditEntry, 0, len(rows))
	for _, a := range rows {
		entries = append(entries, auditEntry{
			ID:         a.ID,
			Action:     a.Action,
			Summary:    a.Summary,
			Detail:     a.Detail,
			RemoteAddr: a.RemoteAddr,
			UserAgent:  a.UserAgent,
			CreatedAt:  a.CreatedAt.Format(time.RFC3339),
		})
	}

	web.JSON(w, http.StatusOK, map[string]any{
		"entries":     entries,
		"page":        page,
		"per_page":    perPage,
		"total":       total,
		"total_pages": totalPages(total, perPage),
	})
}

func totalPages(total int64, perPage int) int {
	if total == 0 {
		return 1
	}
	return int((total + int64(perPage) - 1) / int64(perPage))
}
