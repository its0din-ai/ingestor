package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/diskusage"
	"github.com/encrypt0r/ingestor/internal/filetype"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/users"
	"github.com/encrypt0r/ingestor/internal/web"
)

// maxStoredNameBytes matches the common filesystem limit for a single path
// component. Longer names are rejected before touching the filesystem.
const maxStoredNameBytes = 255

// maxEditableBytes bounds files that can be edited in the browser. Reading is
// streamed and unbounded, but the editor loads the whole document into a
// textarea and sends it back as JSON, so it needs a hard cap.
const maxEditableBytes = 1 << 20 // 1 MiB

// fileMu serializes file mutations (edit saves, delete, rename, quarantine,
// release) and the edit-lock map below. Holding it across the check and the
// filesystem change makes the lease and the mutation atomic with respect to
// each other, so a delete cannot slip in between "is anyone editing?" and
// "remove the file".
var fileMu sync.Mutex

// editLockTTL is how long an editor lease survives without a heartbeat. The
// browser renews every minute; a closed tab (or a dead network) releases the
// file within this window.
const editLockTTL = 5 * time.Minute

type editLock struct {
	token    string
	userID   int64
	username string
	expires  time.Time
}

// editLocks maps a cleaned stored-file path to its active editor lease. It is
// guarded by fileMu.
var editLocks = map[string]editLock{}

// pruneExpiredLocksLocked drops leases that have passed their TTL. Caller
// holds fileMu.
func pruneExpiredLocksLocked(now time.Time) {
	for key, l := range editLocks {
		if !now.Before(l.expires) {
			delete(editLocks, key)
		}
	}
}

// lockHolderLocked returns the username holding a live lease on key. Any live
// lease blocks a mutation: the editing session must close its editor (or lose
// the lease) before the file can be deleted, renamed, quarantined, or released.
// Caller holds fileMu.
func lockHolderLocked(key string, now time.Time) (string, bool) {
	l, ok := editLocks[key]
	if !ok || !now.Before(l.expires) {
		return "", false
	}
	return l.username, true
}

// otherLockHolderLocked is the open-editor variant: the same account may take
// its own lease over (a refreshed or second tab), but another account cannot
// open the file at all.
func otherLockHolderLocked(key string, userID int64, now time.Time) (string, bool) {
	l, ok := editLocks[key]
	if !ok || !now.Before(l.expires) || l.userID == userID {
		return "", false
	}
	return l.username, true
}

// lockLostLocked reports whether token is still the live lease for key.
// Caller holds fileMu.
func lockLostLocked(key, token string, userID int64, now time.Time) bool {
	l, ok := editLocks[key]
	return !ok || l.token != token || l.userID != userID || !now.Before(l.expires)
}

var (
	errNotText  = errors.New("file is not editable text")
	errTooLarge = errors.New("file is too large to edit")
)

// scope resolves the storage directory for the session user. Superadmins
// manage the unowned legacy root; their content endpoints are still refused
// separately.
func (h *Handler) scope(r *http.Request) (dir string, userID int64, u identity.User, ok bool) {
	u, ok = identity.FromRequest(r)
	if !ok {
		return "", 0, u, false
	}
	if u.IsSuperadmin() {
		return h.cfg.UploadDir(), 0, u, true
	}
	if u.IsUser() {
		return users.UserDir(h.cfg.UploadDir(), u.ID), u.ID, u, true
	}
	return "", 0, u, false
}

type fileInfo struct {
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	Modified    time.Time `json:"modified"`
	Quarantined bool      `json:"quarantined"`
	UploaderIP  string    `json:"uploader_ip"`
	Readable    bool      `json:"readable"`
	Editable    bool      `json:"editable"`
	Public      bool      `json:"public"`
	Source      string    `json:"source"`
}

// DiskUsage reports storage consumed by the upload directory plus the
// filesystem totals, so the dashboard can show a disk monitor.
func (h *Handler) DiskUsage(w http.ResponseWriter, r *http.Request) {
	dir, userID, u, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	info, err := diskusage.Summary(dir)
	if err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to read disk usage",
		})
		return
	}
	ownBytes, ownFiles, _ := users.Usage(dir)
	var quotaMB int64
	if u.IsUser() {
		if rec, err := users.Get(h.conn, userID); err == nil {
			quotaMB = rec.QuotaMB
		}
	}
	web.JSON(w, http.StatusOK, map[string]any{
		"upload_dir_bytes": info.UploadDirBytes,
		"used_bytes":       info.UsedBytes,
		"total_bytes":      info.TotalBytes,
		"free_bytes":       info.FreeBytes,
		"free_percent":     math.Round(diskusage.FreePercent(info)*10) / 10,
		"storage_bytes":    ownBytes,
		"storage_files":    ownFiles,
		"quota_mb":         quotaMB,
	})
}

// ListFiles returns the files currently stored in the upload directory.
func (h *Handler) ListFiles(w http.ResponseWriter, r *http.Request) {
	dir, userID, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			web.JSON(w, http.StatusOK, map[string]any{"files": []fileInfo{}})
			return
		}
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
		ip, _ := db.UploaderIP(h.conn, userID, e.Name())
		readable, _ := filetype.IsText(filepath.Join(dir, e.Name()))
		src, _ := db.UploadSource(h.conn, userID, e.Name())
		if src == "" {
			// No record (e.g. a file placed directly on disk): treat it as a
			// browser/manual upload shown in the Files view.
			src = "browser"
		}
		files = append(files, fileInfo{
			Name:        e.Name(),
			Size:        info.Size(),
			Modified:    info.ModTime(),
			Quarantined: strings.HasSuffix(e.Name(), ".quarantined"),
			UploaderIP:  ip,
			Readable:    readable,
			Editable:    readable && info.Size() <= maxEditableBytes,
			Public:      db.IsPublic(h.conn, userID, e.Name()),
			Source:      src,
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Modified.After(files[j].Modified)
	})

	web.JSON(w, http.StatusOK, map[string]any{"files": files})
}

// storedPath validates name as a single path component inside dir, preventing
// traversal, LFI, and header injection. It returns the resolved path and
// whether the name was acceptable.
func (h *Handler) storedPath(dir, name string) (string, bool) {
	return resolveStoredPath(dir, name)
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
	dir, _, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	path, ok := h.storedPath(dir, r.URL.Query().Get("name"))
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
	dir, _, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	path, ok := h.storedPath(dir, r.URL.Query().Get("name"))
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

// EditDocument returns the current text content of a stored file plus a
// content-hash version. The version is what SaveDocument compares against, so
// a stale editor cannot overwrite a newer revision.
func (h *Handler) EditDocument(w http.ResponseWriter, r *http.Request) {
	dir, _, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	name := r.URL.Query().Get("name")
	path, ok := h.storedPath(dir, name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}
	content, version, err := readEditable(path)
	if err != nil {
		editReadError(w, err)
		return
	}
	web.JSON(w, http.StatusOK, editDocument{
		Name:    name,
		Content: string(content),
		Version: version,
		Size:    int64(len(content)),
	})
}

type editDocument struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Version string `json:"version"`
	Size    int64  `json:"size"`
}

// OpenEdit acquires an editor lease and returns the current text plus its
// version. A live lease held by another account blocks the open with 409, so
// two sessions cannot edit the same file at once. Opening again as the same
// account takes the lease over and invalidates an older tab.
func (h *Handler) OpenEdit(w http.ResponseWriter, r *http.Request) {
	dir, userID, u, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid request body",
		})
		return
	}
	path, ok := h.storedPath(dir, req.Name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	now := time.Now()
	pruneExpiredLocksLocked(now)
	if holder, blocked := otherLockHolderLocked(path, userID, now); blocked {
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "file is being edited by " + holder,
		})
		return
	}
	content, version, err := readEditable(path)
	if err != nil {
		editReadError(w, err)
		return
	}
	token := randomToken()
	expires := now.Add(editLockTTL)
	editLocks[path] = editLock{
		token:    token,
		userID:   userID,
		username: u.Username,
		expires:  expires,
	}
	web.JSON(w, http.StatusOK, editOpenResponse{
		editDocument: editDocument{
			Name:    req.Name,
			Content: string(content),
			Version: version,
			Size:    int64(len(content)),
		},
		Lock:      token,
		ExpiresAt: expires.UTC().Format(time.RFC3339),
	})
}

type editOpenResponse struct {
	editDocument
	Lock      string `json:"lock"`
	ExpiresAt string `json:"expires_at"`
}

// RenewEdit extends the editor lease. The browser sends a heartbeat; if the
// lease was lost (expired or taken over), it gets 409 and must reload.
func (h *Handler) RenewEdit(w http.ResponseWriter, r *http.Request) {
	dir, userID, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	var req struct {
		Name string `json:"name"`
		Lock string `json:"lock"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid request body",
		})
		return
	}
	path, ok := h.storedPath(dir, req.Name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	now := time.Now()
	if lockLostLocked(path, req.Lock, userID, now) {
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "edit lock expired or lost; reopen the file",
		})
		return
	}
	l := editLocks[path]
	l.expires = now.Add(editLockTTL)
	editLocks[path] = l
	web.JSON(w, http.StatusOK, map[string]string{
		"status":     "ok",
		"expires_at": l.expires.UTC().Format(time.RFC3339),
	})
}

// CloseEdit releases the editor lease. It is idempotent: a missing or
// mismatched lease is ignored, so a late unload beacon cannot harm a newer
// editor that already took the file over.
func (h *Handler) CloseEdit(w http.ResponseWriter, r *http.Request) {
	dir, userID, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	var req struct {
		Name string `json:"name"`
		Lock string `json:"lock"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid request body",
		})
		return
	}
	path, ok := h.storedPath(dir, req.Name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	fileMu.Lock()
	defer fileMu.Unlock()
	if l, exists := editLocks[path]; exists && l.token == req.Lock && l.userID == userID {
		delete(editLocks, path)
	}
	web.JSON(w, http.StatusOK, web.ErrorResponse{Status: "ok", Message: "Editor closed"})
}

// SaveDocument writes edited text back to a stored file. It requires the
// caller's editor lease and a matching content version, so a stale tab, a
// taken-over lease, or an externally changed file all fail with 409 instead of
// clobbering newer content.
func (h *Handler) SaveDocument(w http.ResponseWriter, r *http.Request) {
	dir, userID, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}

	// JSON adds escaping overhead on top of the document itself; the decoded
	// content is capped separately below.
	r.Body = http.MaxBytesReader(w, r.Body, maxEditableBytes*6+4096)
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
		Version string `json:"version"`
		Lock    string `json:"lock"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			web.JSON(w, http.StatusRequestEntityTooLarge, web.ErrorResponse{
				Status:  "error",
				Message: "file is too large to edit",
			})
			return
		}
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid request body",
		})
		return
	}

	path, ok := h.storedPath(dir, req.Name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}
	if req.Version == "" {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "missing file version",
		})
		return
	}
	if req.Lock == "" {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "missing edit lock",
		})
		return
	}
	content := []byte(req.Content)
	if len(content) > maxEditableBytes {
		web.JSON(w, http.StatusRequestEntityTooLarge, web.ErrorResponse{
			Status:  "error",
			Message: "file is too large to edit",
		})
		return
	}
	if !filetype.IsTextBytes(content) {
		web.JSON(w, http.StatusUnsupportedMediaType, web.ErrorResponse{
			Status:  "error",
			Message: "edited content must be plain text",
		})
		return
	}

	fileMu.Lock()
	defer fileMu.Unlock()

	now := time.Now()
	if lockLostLocked(path, req.Lock, userID, now) {
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "edit lock expired or lost; reload the file before saving",
		})
		return
	}

	old, current, err := readEditable(path)
	if err != nil {
		editReadError(w, err)
		return
	}
	if current != req.Version {
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "file changed since it was opened; reload it before saving",
		})
		return
	}
	if err := writeFileAtomic(path, content); err != nil {
		slog.Warn("failed to save edited file", "name", req.Name, "err", err)
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to save file",
		})
		return
	}

	// Keep the lease alive for a client that continues editing after a save.
	l := editLocks[path]
	l.expires = now.Add(editLockTTL)
	editLocks[path] = l

	h.auditLog.Edit(r, req.Name, int64(len(old)), int64(len(content)))
	web.JSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "File saved",
		"version": contentVersion(content),
	})
}

// readEditable loads a regular text file and returns its content plus version.
// Directories and symlinks are treated as missing, matching the read handlers.
func readEditable(path string) ([]byte, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, "", err
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", os.ErrNotExist
	}
	if info.Size() > maxEditableBytes {
		return nil, "", errTooLarge
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	if !filetype.IsTextBytes(content) {
		return nil, "", errNotText
	}
	return content, contentVersion(content), nil
}

// contentVersion is the optimistic-concurrency token: a digest of the exact
// bytes the editor loaded.
func contentVersion(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeFileAtomic replaces path with content via a temp file in the same
// directory, so readers either see the old file or the new one, never a
// partially written edit. The original permission bits are preserved.
func writeFileAtomic(path string, content []byte) error {
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
		mode = info.Mode().Perm()
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".ingestor-edit-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// editReadError maps readEditable failures onto HTTP responses.
func editReadError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
	case errors.Is(err, errTooLarge):
		web.JSON(w, http.StatusRequestEntityTooLarge, web.ErrorResponse{
			Status:  "error",
			Message: "file is too large to edit",
		})
	case errors.Is(err, errNotText):
		web.JSON(w, http.StatusUnsupportedMediaType, web.ErrorResponse{
			Status:  "error",
			Message: "file is not editable text",
		})
	default:
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to read file",
		})
	}
}

// Quarantine renames a stored file to append the .quarantined suffix so it
// cannot be executed or served as its original type.
func (h *Handler) Quarantine(w http.ResponseWriter, r *http.Request) {
	dir, userID, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	name := r.FormValue("name")
	path, ok := h.storedPath(dir, name)
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
	fileMu.Lock()
	if holder, blocked := lockHolderLocked(path, time.Now()); blocked {
		fileMu.Unlock()
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "file is being edited by " + holder,
		})
		return
	}
	if !h.fileExists(path) {
		fileMu.Unlock()
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}

	target := path + ".quarantined"
	if _, err := os.Stat(target); err == nil {
		fileMu.Unlock()
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "a quarantined file with that name already exists",
		})
		return
	}
	if err := os.Rename(path, target); err != nil {
		fileMu.Unlock()
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to quarantine file",
		})
		return
	}
	delete(editLocks, path)
	fileMu.Unlock()

	_ = db.SetUploadQuarantined(h.conn, userID, name, true)
	if db.IsPublic(h.conn, userID, name) {
		_ = db.MarkPrivate(h.conn, userID, name)
	}
	h.auditLog.Quarantine(r, name)

	web.JSON(w, http.StatusOK, web.ErrorResponse{
		Status:  "ok",
		Message: "File quarantined",
	})
}

// Release removes the .quarantined suffix from a stored file.
func (h *Handler) Release(w http.ResponseWriter, r *http.Request) {
	dir, userID, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	name := r.FormValue("name")
	if !strings.HasSuffix(name, ".quarantined") {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "file is not quarantined",
		})
		return
	}
	path, ok := h.storedPath(dir, name)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}
	base := strings.TrimSuffix(name, ".quarantined")
	basePath, ok := h.storedPath(dir, base)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	fileMu.Lock()
	if holder, blocked := lockHolderLocked(path, time.Now()); blocked {
		fileMu.Unlock()
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "file is being edited by " + holder,
		})
		return
	}
	if !h.fileExists(path) {
		fileMu.Unlock()
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}
	if _, err := os.Stat(basePath); err == nil {
		fileMu.Unlock()
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "the original file name is already taken",
		})
		return
	}
	if err := os.Rename(path, basePath); err != nil {
		fileMu.Unlock()
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to release file",
		})
		return
	}
	delete(editLocks, path)
	fileMu.Unlock()

	_ = db.SetUploadQuarantined(h.conn, userID, base, false)
	h.auditLog.Release(r, base)

	web.JSON(w, http.StatusOK, web.ErrorResponse{
		Status:  "ok",
		Message: "File released from quarantine",
	})
}

// Rename renames a stored file without replacing an existing file. The
// operation is safe under concurrency: the file is moved with a no-replace
// primitive, so when two sessions race on the same source exactly one rename
// wins and the loser gets 404 (source already moved) or 409 (target already
// taken). Nothing is ever silently overwritten.
func (h *Handler) Rename(w http.ResponseWriter, r *http.Request) {
	dir, userID, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}

	oldName := r.FormValue("name")
	oldPath, ok := h.storedPath(dir, oldName)
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	newName, newPath, ok := renameTarget(dir, oldName, r.FormValue("to"))
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid new file name",
		})
		return
	}
	if newName == oldName {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "the file already has that name",
		})
		return
	}
	fileMu.Lock()
	if holder, blocked := lockHolderLocked(oldPath, time.Now()); blocked {
		fileMu.Unlock()
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "file is being edited by " + holder,
		})
		return
	}
	if !h.fileExists(oldPath) {
		fileMu.Unlock()
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}

	renameErr := renameNoReplace(oldPath, newPath)
	if renameErr == nil {
		delete(editLocks, oldPath)
	}
	fileMu.Unlock()

	if renameErr != nil {
		switch {
		case errors.Is(renameErr, fs.ErrExist):
			web.JSON(w, http.StatusConflict, web.ErrorResponse{
				Status:  "error",
				Message: "a file with that name already exists",
			})
		case errors.Is(renameErr, fs.ErrNotExist):
			// Another rename or delete moved the source between the check
			// above and the atomic rename.
			web.JSON(w, http.StatusNotFound, web.ErrorResponse{
				Status:  "error",
				Message: "file not found",
			})
		default:
			slog.Warn("failed to rename file", "from", oldName, "to", newName, "err", renameErr)
			web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
				Status:  "error",
				Message: "failed to rename file",
			})
		}
		return
	}

	// The bytes are already moved; a bookkeeping failure must not report the
	// rename as failed. Log it so the stale row can be repaired.
	if err := db.RenameStored(h.conn, userID, oldName, newName); err != nil {
		slog.Warn("failed to move file records after rename", "from", oldName, "to", newName, "err", err)
	}
	h.auditLog.Rename(r, oldName, newName)

	web.JSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "File renamed",
		"name":    newName,
	})
}

// renameTarget validates a requested new name and returns the final stored
// name and path. Quarantine state is preserved across a rename: a quarantined
// file always keeps the suffix, and a released file cannot be renamed to look
// quarantined by hand.
func renameTarget(dir, oldName, requested string) (name, path string, ok bool) {
	quarantined := strings.HasSuffix(oldName, ".quarantined")
	requested = strings.TrimSpace(requested)
	requested = strings.TrimSuffix(requested, ".quarantined")
	requested = strings.TrimSpace(requested)
	if requested == "" || len(requested) > maxStoredNameBytes {
		return "", "", false
	}
	if quarantined {
		requested += ".quarantined"
	}
	path, ok = resolveStoredPath(dir, requested)
	if !ok {
		return "", "", false
	}
	return requested, path, true
}

// renameNoReplace renames src to dst and never replaces an existing dst.
//
// os.Rename silently overwrites on POSIX, so a Stat-then-Rename check is racy:
// two concurrent renames can clobber each other. The destination is therefore
// claimed first with O_EXCL, which the kernel resolves atomically: exactly one
// racing caller can create dst, everyone else gets fs.ErrExist. The claim is a
// zero-byte placeholder that the rename immediately replaces. If the rename
// fails the placeholder is removed again, so a failed call leaves no trace.
//
// (Hard links were considered for this, but concurrent unlink of the same name
// returns success more than once on macOS APFS, so they cannot arbitrate.)
func renameNoReplace(src, dst string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
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
	dir, userID, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	name := r.FormValue("name")
	path, ok := h.storedPath(dir, name)
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

	if err := db.MarkPublic(h.conn, userID, name); err != nil {
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
	dir, userID, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	name := r.FormValue("name")
	path, ok := h.storedPath(dir, name)
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

	if err := db.MarkPrivate(h.conn, userID, name); err != nil {
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
	userID := int64(0)
	if raw := r.URL.Query().Get("u"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 1 {
			h.auditLog.PublicDenied(r, r.URL.Query().Get("name"), "invalid_owner")
			web.JSON(w, http.StatusNotFound, web.ErrorResponse{
				Status:  "error",
				Message: "file not available",
			})
			return
		}
		userID = id
	}
	dir := h.cfg.UploadDir()
	if userID > 0 {
		dir = users.UserDir(h.cfg.UploadDir(), userID)
	}

	requested := r.URL.Query().Get("name")
	path, ok := h.storedPath(dir, requested)
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
	if strings.HasSuffix(name, ".quarantined") || !db.IsPublic(h.conn, userID, name) {
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
	dir, userID, _, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	path, ok := h.storedPath(dir, r.FormValue("name"))
	if !ok {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	fileMu.Lock()
	now := time.Now()
	if holder, blocked := lockHolderLocked(path, now); blocked {
		fileMu.Unlock()
		web.JSON(w, http.StatusConflict, web.ErrorResponse{
			Status:  "error",
			Message: "file is being edited by " + holder,
		})
		return
	}
	if !h.fileExists(path) {
		fileMu.Unlock()
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}

	if err := os.Remove(path); err != nil {
		fileMu.Unlock()
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to delete file",
		})
		return
	}
	delete(editLocks, path)
	fileMu.Unlock()
	// A deleted file must not leave behind a public grant that a future
	// upload with the same name would inherit.
	_ = db.MarkPrivate(h.conn, userID, filepath.Base(path))

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

	_, userID, u, ok := h.scope(r)
	if !ok {
		web.JSON(w, http.StatusForbidden, web.ErrorResponse{Status: "error", Message: "forbidden"})
		return
	}
	filter := int64(-1)
	if !u.IsSuperadmin() {
		filter = userID
	}

	total, err := db.CountAudit(h.conn, filter)
	if err != nil {
		web.JSON(w, http.StatusInternalServerError, web.ErrorResponse{
			Status:  "error",
			Message: "failed to count audit log",
		})
		return
	}

	rows, err := db.ListAudit(h.conn, filter, perPage, (page-1)*perPage)
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
		UALabel    string `json:"ua_label"`
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
			UALabel:    uaLabel(a.UserAgent),
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
