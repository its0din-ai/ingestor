package upload

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
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
	"github.com/encrypt0r/ingestor/internal/logging"
	"github.com/encrypt0r/ingestor/internal/quarantine"
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

func New(cfg *config.Config, conn *sql.DB, auditLog *audit.Logger) *Handler {
	return &Handler{cfg: cfg, conn: conn, auditLog: auditLog}
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
	maxBytes := h.cfg.MaxUploadBytes()
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		h.handleMultipart(w, r, maxBytes)
		return
	}
	h.handleRaw(w, r, maxBytes)
}

func (h *Handler) handleMultipart(w http.ResponseWriter, r *http.Request, maxBytes int64) {
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
		h.save(w, r, part, sanitizeName(part.FileName()), maxBytes)
		_ = part.Close()
		return
	}

	h.fail(w, http.StatusBadRequest, "no file part found")
}

func (h *Handler) handleRaw(w http.ResponseWriter, r *http.Request, maxBytes int64) {
	name := sanitizeName(rawFilename(r))
	if name == "" {
		name = "upload-" + strconv.FormatInt(time.Now().Unix(), 10)
	}
	h.save(w, r, r.Body, name, maxBytes)
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

func (h *Handler) save(w http.ResponseWriter, r *http.Request, src io.Reader, name string, maxBytes int64) {
	dir := h.cfg.UploadDir()
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
	if err := tmp.Close(); err != nil {
		h.fail(w, http.StatusInternalServerError, "failed to finalize file")
		return
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		h.fail(w, http.StatusInternalServerError, "failed to set file permissions")
		return
	}

	quarantined := quarantine.IsQuarantined(name, h.cfg.QuarantineExtensions())

	finalName := suffixRandom(name)
	if quarantined {
		finalName += ".quarantined"
	}
	finalPath := filepath.Join(dir, finalName)
	// Guard against a name collision from a concurrent upload with the same
	// random suffix: os.Rename would silently overwrite, so retry with a
	// fresh suffix.
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

	if err := os.Rename(tmpName, finalPath); err != nil {
		h.fail(w, http.StatusInternalServerError, "failed to move file")
		return
	}
	if err := os.Chmod(finalPath, 0o644); err != nil {
		h.fail(w, http.StatusInternalServerError, "failed to set file permissions")
		return
	}

	if err := db.InsertUpload(h.conn, db.UploadRecord{
		OriginalName: name,
		StoredName:   finalName,
		FileSize:     written,
		Quarantined:  quarantined,
		RemoteAddr:   logging.ClientIP(r),
		CreatedAt:    time.Now(),
	}); err != nil {
		slog.Warn("failed to record upload", "err", err)
	}

	tokenID, tokenLabel := "", ""
	if id, ok := auth.BearerIdentityFromContext(r); ok {
		tokenID, tokenLabel = id.ID, id.Label
	}

	h.auditLog.Upload(logging.ClientIP(r), name, finalName, written, quarantined, tokenID, tokenLabel)

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
		if r < 0x20 || r == 0x7f {
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
