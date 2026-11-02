package upload

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/encrypt0r/ingestor/internal/identity"
)

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"report.pdf", "report.pdf"},
		{"../../etc/passwd", "passwd"},
		{`C:\Users\evil.txt`, "evil.txt"},
		{"../../etc/passwd", "passwd"},
		{"..hidden", "hidden"},
		{"normal.txt", "normal.txt"},
		{"a\x00b.txt", "ab.txt"},
		{"path/to/file.bin", "file.bin"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeName(tt.name); got != tt.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestRandomHexLength(t *testing.T) {
	if got := randomHex(6); len(got) != 12 {
		t.Errorf("randomHex(6) length = %d, want 12", len(got))
	}
}

func TestSuffixRandom(t *testing.T) {
	got := suffixRandom("report.pdf")
	if !strings.HasPrefix(got, "report_") {
		t.Errorf("suffixRandom should keep base first, got %q", got)
	}
	if !strings.HasSuffix(got, ".pdf") {
		t.Errorf("suffixRandom should keep extension last, got %q", got)
	}
	// base + "_" + 12 hex + ".pdf"
	if len(got) != len("report")+1+12+len(".pdf") {
		t.Errorf("suffixRandom length = %d, got %q", len(got), got)
	}

	// no extension
	got = suffixRandom("README")
	if !strings.HasPrefix(got, "README_") {
		t.Errorf("suffixRandom should keep base first, got %q", got)
	}
	if strings.HasSuffix(got, ".") {
		t.Errorf("suffixRandom with no extension should not end with dot, got %q", got)
	}
}

func multipartRequest(t *testing.T, target, partName, fileName, content string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(partName, fileName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, target, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func withIdentity(req *http.Request, u identity.User) *http.Request {
	return req.WithContext(identity.WithUser(req.Context(), u))
}

func singleStoredName(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("stored files = %d, want 1", len(entries))
	}
	return entries[0].Name()
}

func TestUploadNamePrecedence(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/upload?name=query.txt", nil)
	req.Header.Set("Content-Disposition", `attachment; filename="header.txt"`)
	if got := uploadName(req, rawFilename(req)); got != "query.txt" {
		t.Fatalf("query should win, got %q", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/upload", nil)
	req.Header.Set("Content-Disposition", `attachment; filename="header.txt"`)
	if got := uploadName(req, rawFilename(req)); got != "header.txt" {
		t.Fatalf("header fallback = %q", got)
	}
	if got := uploadName(req, "part.txt"); got != "part.txt" {
		t.Fatalf("part fallback = %q", got)
	}

	// Empty or hostile query values fall back instead of escaping the dir.
	if got := uploadName(httptest.NewRequest(http.MethodPost, "/upload?name=", nil), "part.txt"); got != "part.txt" {
		t.Fatalf("empty query fallback = %q", got)
	}
	if got := uploadName(httptest.NewRequest(http.MethodPost, "/upload?name=../../etc/passwd", nil), "part.txt"); got != "passwd" {
		t.Fatalf("query sanitization = %q, want passwd", got)
	}
}

func TestMultipartQueryNameWins(t *testing.T) {
	h, _ := testUploadHandler(t)
	req := multipartRequest(t, "/upload?name=query-name.txt", "file", "part-name.txt", "hello")
	req = withIdentity(req, identity.User{Role: identity.RoleLegacy})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if name := singleStoredName(t, h.cfg.UploadDir()); name != "query-name.txt" {
		t.Fatalf("stored name = %q, want query-name.txt", name)
	}
}

func TestMultipartFallsBackToPartName(t *testing.T) {
	h, _ := testUploadHandler(t)
	req := multipartRequest(t, "/upload", "file", "part-name.txt", "hello")
	req = withIdentity(req, identity.User{Role: identity.RoleLegacy})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	name := singleStoredName(t, h.cfg.UploadDir())
	if !strings.HasPrefix(name, "part-name_") || !strings.HasSuffix(name, ".txt") {
		t.Fatalf("stored name = %q, want part-name_<rand>.txt", name)
	}
}

func TestMultipartQueryNameIsSanitized(t *testing.T) {
	h, _ := testUploadHandler(t)
	req := multipartRequest(t, "/upload?name=../../etc/passwd", "file", "part.txt", "hello")
	req = withIdentity(req, identity.User{Role: identity.RoleLegacy})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if name := singleStoredName(t, h.cfg.UploadDir()); name != "passwd" {
		t.Fatalf("stored name = %q, want passwd", name)
	}
}

func TestBrowserUploadQueryNameIsExact(t *testing.T) {
	h, _ := testUploadHandler(t)
	req := multipartRequest(t, "/dashboard/upload?name=chosen.txt", "file", "part.txt", "hello")
	req = withIdentity(req, identity.User{ID: 1, Username: "admin", Role: identity.RoleSuperadmin})

	rec := httptest.NewRecorder()
	h.UploadBrowser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if name := singleStoredName(t, h.cfg.UploadDir()); name != "chosen.txt" {
		t.Fatalf("stored name = %q, want chosen.txt", name)
	}
}

func TestRawQueryNameWinsOverHeader(t *testing.T) {
	h, _ := testUploadHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/upload?name=query.txt", strings.NewReader("x"))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Disposition", `attachment; filename="header.txt"`)
	req = withIdentity(req, identity.User{Role: identity.RoleLegacy})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if name := singleStoredName(t, h.cfg.UploadDir()); name != "query.txt" {
		t.Fatalf("stored name = %q, want query.txt", name)
	}
}

func TestMultipartQueryNameRefusesOverwrite(t *testing.T) {
	h, _ := testUploadHandler(t)
	if err := os.MkdirAll(h.cfg.UploadDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(h.cfg.UploadDir(), "taken.txt")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	req := multipartRequest(t, "/upload?name=taken.txt", "file", "part.txt", "new")
	req = withIdentity(req, identity.User{Role: identity.RoleLegacy})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", rec.Code, rec.Body.String())
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "old" {
		t.Fatalf("existing file changed: %q, %v", got, err)
	}
}
