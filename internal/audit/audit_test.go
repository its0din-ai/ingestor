package audit

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/encrypt0r/ingestor/internal/db"
)

func TestUploadSummaryPrefersLabel(t *testing.T) {
	conn, err := db.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	l := New(conn)

	req := httptest.NewRequest(http.MethodPost, "/upload", nil)

	// Without a label: fall back to the token id.
	l.Upload(req, "r.txt", "r_abc.txt", 10, false, "a3f9c2", "")
	// With a label: prefer the label.
	l.Upload(req, "r.txt", "r_abc.txt", 10, false, "a3f9c2", "alice")

	rows, err := db.ListAudit(conn, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 2 {
		t.Fatalf("got %d audit rows, want 2", len(rows))
	}
	// ListAudit is ordered newest first.
	if got := rows[0].Summary; got != "bearer token alice used for upload: r.txt" {
		t.Errorf("label summary = %q", got)
	}
	if got := rows[1].Summary; got != "bearer token id a3f9c2 used for upload: r.txt" {
		t.Errorf("id fallback summary = %q", got)
	}
}

func TestUploadSummaryViaCfProxy(t *testing.T) {
	conn, err := db.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	l := New(conn)

	req := httptest.NewRequest(http.MethodPost, "/upload", nil)
	req.Header.Set("X-Morph-Real-Ip", "198.51.100.44")
	l.Upload(req, "data.txt", "data_abc.txt", 10, false, "a3f9c2", "production")

	rows, err := db.ListAudit(conn, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d audit rows, want 1", len(rows))
	}
	want := "bearer token production used for upload: data.txt via cf-proxy"
	if got := rows[0].Summary; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
}
