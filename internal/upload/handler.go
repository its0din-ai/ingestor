package upload

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/encrypt0r/ingestor/internal/audit"
	"github.com/encrypt0r/ingestor/internal/auth"
	"github.com/encrypt0r/ingestor/internal/config"
	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/logging"
	"github.com/encrypt0r/ingestor/internal/quarantine"
	"github.com/encrypt0r/ingestor/internal/users"
	"github.com/encrypt0r/ingestor/internal/web"
)

type response struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	Size        int64  `json:"size"`
	Quarantined bool   `json:"quarantined"`
	Timestamp   string `json:"timestamp"`
}

type Handler struct {
	cfg      *config.Config
	conn     *sql.DB
	auditLog *audit.Logger
}

// owner describes where an upload is stored and how much space it may use.
type owner struct {
	userID  int64
	dir     string
	quotaMB int64
}

var (
	errNoIdentity = errors.New("no authenticated owner")
	errNoStorage  = errors.New("account has no storage")
)

func New(cfg *config.Config, conn *sql.DB, auditLog *audit.Logger) *Handler {
	return &Handler{cfg: cfg, conn: conn, auditLog: auditLog}
}

// ownerFor resolves the storage root for the authenticated principal. Legacy
// bearer tokens (identity role "legacy") write to the unowned upload root.
func (h *Handler) ownerFor(r *http.Request) (owner, error) {
	u, ok := identity.FromRequest(r)
	if !ok {
		return owner{}, errNoIdentity
	}
	if u.Role == identity.RoleLegacy || u.IsSuperadmin() {
		// The superadmin keeps the original upload root as personal storage,
		// preserving the pre-multi-user behavior. Regular users are isolated
		// under upload_dir/users/<id>.
		return owner{userID: 0, dir: h.cfg.UploadDir()}, nil
	}
	if !u.IsUser() {
		return owner{}, errNoStorage
	}
	rec, err := users.Get(h.conn, u.ID)
	if err != nil || rec.Disabled {
		return owner{}, errNoStorage
	}
	return owner{
		userID:  rec.ID,
		dir:     users.UserDir(h.cfg.UploadDir(), rec.ID),
		quotaMB: rec.QuotaMB,
	}, nil
}

// ServeHTTP is the catch-all: non-upload methods are logged and acked;
// POST/PUT with a body are stored as uploads.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		h.handleUpload(w, r)
	default:
		web.JSON(w, http.StatusOK, web.ErrorResponse{
			Status:  "ok",
			Message: "logged",
		})
	}
}

func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request) {
	o, err := h.ownerFor(r)
	if err != nil {
		h.ownerFail(w, err)
		return
	}
	maxBytes := h.cfg.MaxUploadBytes()
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		h.handleMultipart(w, r, maxBytes, o)
		return
	}
	h.handleRaw(w, r, maxBytes, o)
}

func (h *Handler) ownerFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNoIdentity):
		h.fail(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, errNoStorage):
		h.fail(w, http.StatusForbidden, "this account has no storage")
	default:
		h.fail(w, http.StatusInternalServerError, "failed to resolve storage")
	}
}

func (h *Handler) handleMultipart(w http.ResponseWriter, r *http.Request, maxBytes int64, o owner) {
	reader, err := r.MultipartReader()
	if err != nil {
		h.fail(w, http.StatusBadRequest, "invalid multipart request")
		return
	}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			h.fail(w, http.StatusBadRequest, "invalid multipart part")
			return
		}
		if part.FileName() == "" {
			continue
		}
		h.save(w, r, part, sanitizeName(part.FileName()), maxBytes, false, "api", o)
		_ = part.Close()
		return
	}

	h.fail(w, http.StatusBadRequest, "no file part found")
}

func (h *Handler) handleRaw(w http.ResponseWriter, r *http.Request, maxBytes int64, o owner) {
	name := sanitizeName(rawFilename(r))
	if name == "" {
		name = "upload-" + strconv.FormatInt(time.Now().Unix(), 10)
	}
	h.save(w, r, r.Body, name, maxBytes, false, "api", o)
}

// UploadBrowser stores a multipart file using its original name (no random
// suffix), for session-authenticated browser uploads from the dashboard. If
// a file with the same name already exists the upload is refused so nothing
// is silently overwritten.
func (h *Handler) UploadBrowser(w http.ResponseWriter, r *http.Request) {
	o, err := h.ownerFor(r)
	if err != nil {
		h.ownerFail(w, err)
		return
	}
	maxBytes := h.cfg.MaxUploadBytes()
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	reader, err := r.MultipartReader()
	if err != nil {
		h.fail(w, http.StatusBadRequest, "invalid multipart request")
		return
	}

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			h.fail(w, http.StatusBadRequest, "invalid multipart part")
			return
		}
		if part.FileName() == "" {
			continue
		}
		h.save(w, r, part, sanitizeName(part.FileName()), maxBytes, true, "browser", o)
		_ = part.Close()
		return
	}

	h.fail(w, http.StatusBadRequest, "no file part found")
}

func rawFilename(r *http.Request) string {
	if name := r.URL.Query().Get("name"); name != "" {
		return name
	}
	if disp := r.Header.Get("Content-Disposition"); disp != "" {
		_, params, err := mime.ParseMediaType(disp)
		if err == nil && params["filename"] != "" {
			return params["filename"]
		}
	}
	return ""
}

// save streams src into the upload dir as name. When keepName is true the
// name is used verbatim (refusing to overwrite an existing file); otherwise
// a random suffix is appended so concurrent arbitrary uploads never collide.
// source records how the file arrived ("api" for the token endpoint,
// "browser" for the dashboard upload) so the Files view can be split.
func (h *Handler) save(w http.ResponseWriter, r *http.Request, src io.Reader, name string, maxBytes int64, keepName bool, source string, o owner) {
	dir := o.dir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		h.fail(w, http.StatusInternalServerError, "failed to prepare upload directory")
		return
	}

	tmp, err := os.CreateTemp(dir, ".ingestor-*.tmp")
	if err != nil {
		h.fail(w, http.StatusInternalServerError, "failed to create temp file")
		return
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	written, err := io.Copy(tmp, io.LimitReader(src, maxBytes+1))
	if err != nil {
		_ = tmp.Close()
		h.fail(w, http.StatusInternalServerError, "failed to write file")
		return
	}
	if written > maxBytes {
		_ = tmp.Close()
		h.fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("file exceeds maximum upload size of %d MB", h.cfg.MaxUploadMB()))
		return
	}
	if o.quotaMB > 0 {
		used, _, err := users.Usage(dir)
		if err != nil {
			_ = tmp.Close()
			h.fail(w, http.StatusInternalServerError, "failed to read storage usage")
			return
		}
		quotaBytes := o.quotaMB * 1024 * 1024
		if used+written > quotaBytes {
			_ = tmp.Close()
			h.fail(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("storage quota exceeded: %d of %d MB used", used/(1024*1024), o.quotaMB))
			return
		}
	}
	if err := tmp.Close(); err != nil {
		h.fail(w, http.StatusInternalServerError, "failed to finalize file")
		return
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		h.fail(w, http.StatusInternalServerError, "failed to set file permissions")
		return
	}

	quarantined := quarantine.IsQuarantined(name, h.cfg.QuarantineExtensions())

	finalName := name
	if !keepName {
		finalName = suffixRandom(name)
	}
	if quarantined {
		finalName += ".quarantined"
	}
	finalPath := filepath.Join(dir, finalName)

	if keepName {
		// Browser uploads keep the original name: refuse to silently
		// overwrite an existing file.
		if _, err := os.Stat(finalPath); err == nil {
			h.fail(w, http.StatusConflict, "a file with that name already exists")
			return
		}
	} else {
		// Guard against a name collision from a concurrent upload with the
		// same random suffix: os.Rename would silently overwrite, so retry
		// with a fresh suffix.
		for i := 0; i < 5; i++ {
			if _, err := os.Stat(finalPath); os.IsNotExist(err) {
				break
			}
			finalName = suffixRandom(name)
			if quarantined {
				finalName += ".quarantined"
			}
			finalPath = filepath.Join(dir, finalName)
		}
	}
	// If every retry still collided, fail instead of letting os.Rename
	// silently overwrite an existing file.
	if _, err := os.Stat(finalPath); err == nil {
		h.fail(w, http.StatusConflict, "a file with that name already exists")
		return
	}

	if err := os.Rename(tmpName, finalPath); err != nil {
		h.fail(w, http.StatusInternalServerError, "failed to move file")
		return
	}
	if err := os.Chmod(finalPath, 0o644); err != nil {
		h.fail(w, http.StatusInternalServerError, "failed to set file permissions")
		return
	}

	if err := db.InsertUpload(h.conn, db.UploadRecord{
		UserID:       o.userID,
		OriginalName: name,
		StoredName:   finalName,
		FileSize:     written,
		Quarantined:  quarantined,
		RemoteAddr:   logging.ClientIP(r),
		Source:       source,
		CreatedAt:    time.Now(),
	}); err != nil {
		slog.Warn("failed to record upload", "err", err)
	}

	tokenID, tokenLabel := "", ""
	if id, ok := auth.BearerIdentityFromContext(r); ok {
		tokenID, tokenLabel = id.ID, id.Label
	}

	h.auditLog.Upload(r, name, finalName, written, quarantined, tokenID, tokenLabel)

	level := slog.LevelInfo
	if quarantined {
		level = slog.LevelWarn
	}
	slog.Log(r.Context(), level, "upload",
		"original_name", name,
		"size", written,
		"quarantined", quarantined,
		"remote", logging.ClientIP(r),
	)

	web.JSON(w, http.StatusOK, response{
		Status:      "ok",
		Message:     "File received",
		Size:        written,
		Quarantined: quarantined,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *Handler) fail(w http.ResponseWriter, status int, message string) {
	web.JSON(w, status, web.ErrorResponse{
		Status:  "error",
		Message: message,
	})
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// suffixRandom appends the random hex after the base filename so files sort by
// their original name: {base}_{rand}.{ext}.
func suffixRandom(name string) string {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	return base + "_" + randomHex(6) + ext
}

func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	name = strings.Trim(name, "/")
	if len(name) >= 2 && name[1] == ':' {
		name = name[2:]
	}
	name = strings.TrimLeft(name, ".")
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' {
			return -1
		}
		return r
	}, name)

	runes := []rune(name)
	if len(runes) > 255 {
		runes = runes[:255]
	}
	name = string(runes)
	return name
}
