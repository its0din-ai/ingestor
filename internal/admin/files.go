package admin

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/web"
)

type fileInfo struct {
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	Modified    time.Time `json:"modified"`
	Quarantined bool      `json:"quarantined"`
	UploaderIP  string    `json:"uploader_ip"`
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
		ip, _ := db.UploaderIP(h.conn, e.Name())
		files = append(files, fileInfo{
			Name:        e.Name(),
			Size:        info.Size(),
			Modified:    info.ModTime(),
			Quarantined: strings.HasSuffix(e.Name(), ".quarantined"),
			UploaderIP:  ip,
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Modified.After(files[j].Modified)
	})

	web.JSON(w, http.StatusOK, map[string]any{"files": files})
}

// Download serves a stored file. The name is sanitized to a single path
// component to prevent traversal outside the upload directory.
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("name"))
	if name == "." || name == "" {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	path := filepath.Join(h.cfg.UploadDir(), name)
	if !strings.HasPrefix(path, filepath.Clean(h.cfg.UploadDir())+string(os.PathSeparator)) {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		web.JSON(w, http.StatusNotFound, web.ErrorResponse{
			Status:  "error",
			Message: "file not found",
		})
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	http.ServeFile(w, r, path)
}

// Delete removes a stored file.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.FormValue("name"))
	if name == "." || name == "" {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	path := filepath.Join(h.cfg.UploadDir(), name)
	if !strings.HasPrefix(path, filepath.Clean(h.cfg.UploadDir())+string(os.PathSeparator)) {
		web.JSON(w, http.StatusBadRequest, web.ErrorResponse{
			Status:  "error",
			Message: "invalid file name",
		})
		return
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
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

	web.JSON(w, http.StatusOK, web.ErrorResponse{
		Status:  "ok",
		Message: "File deleted",
	})
}
