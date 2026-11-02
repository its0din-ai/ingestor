package admin

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/users"
)

func editGet(t *testing.T, h *Handler, u identity.User, name string) (int, editDocument, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/edit?name="+url.QueryEscape(name), nil)
	req = withUser(req, u)
	rec := httptest.NewRecorder()
	h.EditDocument(rec, req)
	var doc editDocument
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	return rec.Code, doc, rec.Body.String()
}

func editOpen(t *testing.T, h *Handler, u identity.User, name string) (int, editOpenResponse, string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/edit/open", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUser(req, u)
	rec := httptest.NewRecorder()
	h.OpenEdit(rec, req)
	var resp editOpenResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, resp, rec.Body.String()
}

func editSave(t *testing.T, h *Handler, u identity.User, name, content, version, lock string) (int, string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"name":    name,
		"content": content,
		"version": version,
		"lock":    lock,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/edit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUser(req, u)
	rec := httptest.NewRecorder()
	h.SaveDocument(rec, req)
	return rec.Code, rec.Body.String()
}

func editClose(t *testing.T, h *Handler, u identity.User, name, lock string) (int, string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"name": name, "lock": lock})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/edit/close", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withUser(req, u)
	rec := httptest.NewRecorder()
	h.CloseEdit(rec, req)
	return rec.Code, rec.Body.String()
}

func editUser(t *testing.T, h *Handler, conn *sql.DB, name string) (identity.User, string) {
	t.Helper()
	u, err := users.Create(conn, name, "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	return identity.User{ID: u.ID, Username: name, Role: identity.RoleUser}, users.UserDir(h.cfg.UploadDir(), u.ID)
}

func setTestLock(path string, l editLock) {
	fileMu.Lock()
	editLocks[path] = l
	fileMu.Unlock()
}

func getTestLock(path string) (editLock, bool) {
	fileMu.Lock()
	defer fileMu.Unlock()
	l, ok := editLocks[path]
	return l, ok
}

func TestEditRoundTrip(t *testing.T) {
	h, conn := testHandler(t)
	u, dir := editUser(t, h, conn, "alice")
	writeUserFile(t, h, u.ID, "notes.txt", "hello\n")

	code, doc, body := editOpen(t, h, u, "notes.txt")
	if code != http.StatusOK {
		t.Fatalf("open status = %d, body = %s", code, body)
	}
	if doc.Content != "hello\n" || doc.Version == "" || doc.Lock == "" {
		t.Fatalf("open response = %+v", doc)
	}

	code, body = editSave(t, h, u, "notes.txt", "hello\nworld\n", doc.Version, doc.Lock)
	if code != http.StatusOK {
		t.Fatalf("save status = %d, body = %s", code, body)
	}
	if got := readFile(t, filepath.Join(dir, "notes.txt")); got != "hello\nworld\n" {
		t.Fatalf("content = %q", got)
	}

	_, doc2, _ := editGet(t, h, u, "notes.txt")
	if doc2.Version == doc.Version {
		t.Fatal("version did not change after save")
	}
}

func TestEditRejectsStaleVersion(t *testing.T) {
	h, conn := testHandler(t)
	u, dir := editUser(t, h, conn, "alice")
	writeUserFile(t, h, u.ID, "notes.txt", "one")

	_, doc, _ := editOpen(t, h, u, "notes.txt")

	// Another writer replaces the file after this editor loaded it.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, body := editSave(t, h, u, "notes.txt", "stale-write", doc.Version, doc.Lock)
	if code != http.StatusConflict {
		t.Fatalf("stale save = %d, want 409; body = %s", code, body)
	}
	if got := readFile(t, filepath.Join(dir, "notes.txt")); got != "two" {
		t.Fatalf("file was overwritten by a stale editor: %q", got)
	}
}

// TestEditConcurrentSaves races several editors that all loaded the same
// version. Exactly one save must win; every other save must be rejected, and
// the surviving file must be one complete winner payload.
func TestEditConcurrentSaves(t *testing.T) {
	h, conn := testHandler(t)
	u, dir := editUser(t, h, conn, "alice")
	writeUserFile(t, h, u.ID, "race.txt", "start")

	_, doc, _ := editOpen(t, h, u, "race.txt")

	const n = 8
	contents := make([]string, n)
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		contents[i] = fmt.Sprintf("editor-%d-payload", i)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i], _ = editSave(t, h, u, "race.txt", contents[i], doc.Version, doc.Lock)
		}(i)
	}
	close(start)
	wg.Wait()

	wins, winner := 0, -1
	for i, code := range codes {
		switch code {
		case http.StatusOK:
			wins++
			winner = i
		case http.StatusConflict:
			// Lost the compare-and-swap; expected.
		default:
			t.Errorf("save %d returned unexpected status %d", i, code)
		}
	}
	if wins != 1 {
		t.Fatalf("%d saves succeeded, want exactly 1 (codes = %v)", wins, codes)
	}
	if got := readFile(t, filepath.Join(dir, "race.txt")); got != contents[winner] {
		t.Fatalf("final content = %q, want winner %q", got, contents[winner])
	}

	// Atomic writes must not leave temp files behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".ingestor-edit-") {
			t.Fatalf("leftover temp file %q", e.Name())
		}
	}
}

func TestEditRequiresMatchingLease(t *testing.T) {
	h, conn := testHandler(t)
	u, dir := editUser(t, h, conn, "alice")
	writeUserFile(t, h, u.ID, "notes.txt", "text")
	_, doc, _ := editOpen(t, h, u, "notes.txt")

	if code, body := editSave(t, h, u, "notes.txt", "new", doc.Version, ""); code != http.StatusBadRequest {
		t.Fatalf("missing lock = %d, want 400; body = %s", code, body)
	}
	if code, body := editSave(t, h, u, "notes.txt", "new", doc.Version, "wrong"); code != http.StatusConflict {
		t.Fatalf("wrong lock = %d, want 409; body = %s", code, body)
	}
	if got := readFile(t, filepath.Join(dir, "notes.txt")); got != "text" {
		t.Fatalf("file changed after rejected saves: %q", got)
	}
}

func TestEditOpenRejectsForeignLease(t *testing.T) {
	h, conn := testHandler(t)
	alice, dir := editUser(t, h, conn, "alice")
	writeUserFile(t, h, alice.ID, "notes.txt", "text")
	path := filepath.Join(dir, "notes.txt")

	setTestLock(path, editLock{
		token:    "foreign-token",
		userID:   999,
		username: "bob",
		expires:  time.Now().Add(time.Minute),
	})

	code, _, body := editOpen(t, h, alice, "notes.txt")
	if code != http.StatusConflict || !strings.Contains(body, "bob") {
		t.Fatalf("foreign lease open = %d, want 409 naming bob; body = %s", code, body)
	}

	// The same account may take the lease over (e.g. a refreshed tab), which
	// invalidates the previous token.
	setTestLock(path, editLock{
		token:    "old-token",
		userID:   alice.ID,
		username: "alice",
		expires:  time.Now().Add(time.Minute),
	})
	code, doc, body := editOpen(t, h, alice, "notes.txt")
	if code != http.StatusOK {
		t.Fatalf("own lease takeover = %d, body = %s", code, body)
	}
	if doc.Lock == "old-token" {
		t.Fatal("takeover did not issue a new token")
	}
}

func TestEditDeleteAndRenameBlockedByLease(t *testing.T) {
	h, conn := testHandler(t)
	alice, dir := editUser(t, h, conn, "alice")
	writeUserFile(t, h, alice.ID, "notes.txt", "text")
	path := filepath.Join(dir, "notes.txt")

	setTestLock(path, editLock{
		token:    "foreign-token",
		userID:   999,
		username: "bob",
		expires:  time.Now().Add(time.Minute),
	})

	delReq := withUser(httptest.NewRequest(http.MethodPost, "/dashboard/delete",
		strings.NewReader("name=notes.txt")), alice)
	delReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	delRec := httptest.NewRecorder()
	h.Delete(delRec, delReq)
	if delRec.Code != http.StatusConflict {
		t.Fatalf("delete with foreign lease = %d, want 409; body = %s", delRec.Code, delRec.Body.String())
	}
	if got := readFile(t, path); got != "text" {
		t.Fatalf("file deleted despite lease: %q", got)
	}

	if code, _ := doRename(t, h, alice, "notes.txt", "moved.txt"); code != http.StatusConflict {
		t.Fatalf("rename with foreign lease = %d, want 409", code)
	}
	if got := readFile(t, path); got != "text" {
		t.Fatalf("file renamed despite lease: %q", got)
	}

	// Any live lease blocks, even one held by the same account; the editor
	// must close (or let the lease expire) before the file can be removed.
	setTestLock(path, editLock{
		token:    "own-token",
		userID:   alice.ID,
		username: "alice",
		expires:  time.Now().Add(time.Minute),
	})
	delRec = httptest.NewRecorder()
	delReq = withUser(httptest.NewRequest(http.MethodPost, "/dashboard/delete",
		strings.NewReader("name=notes.txt")), alice)
	delReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Delete(delRec, delReq)
	if delRec.Code != http.StatusConflict {
		t.Fatalf("delete with own lease = %d, want 409; body = %s", delRec.Code, delRec.Body.String())
	}

	// Releasing the lease allows the delete, and the lease is cleaned up.
	if code, body := editClose(t, h, alice, "notes.txt", "own-token"); code != http.StatusOK {
		t.Fatalf("close = %d, body = %s", code, body)
	}
	delRec = httptest.NewRecorder()
	delReq = withUser(httptest.NewRequest(http.MethodPost, "/dashboard/delete",
		strings.NewReader("name=notes.txt")), alice)
	delReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Delete(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete after close = %d, body = %s", delRec.Code, delRec.Body.String())
	}
	if _, ok := getTestLock(path); ok {
		t.Fatal("lease was not released after delete")
	}
}

func TestEditLeaseExpiryAndClose(t *testing.T) {
	h, conn := testHandler(t)
	alice, dir := editUser(t, h, conn, "alice")
	writeUserFile(t, h, alice.ID, "notes.txt", "text")
	path := filepath.Join(dir, "notes.txt")

	// An expired lease is pruned and never blocks.
	setTestLock(path, editLock{
		token:    "expired",
		userID:   999,
		username: "bob",
		expires:  time.Now().Add(-time.Second),
	})
	code, doc, body := editOpen(t, h, alice, "notes.txt")
	if code != http.StatusOK {
		t.Fatalf("open past expired lease = %d, body = %s", code, body)
	}

	// Closing releases the lease, after which another account could open it.
	if code, body := editClose(t, h, alice, "notes.txt", doc.Lock); code != http.StatusOK {
		t.Fatalf("close = %d, body = %s", code, body)
	}
	if _, ok := getTestLock(path); ok {
		t.Fatal("close did not release the lease")
	}
}

func TestEditRejectsBinary(t *testing.T) {
	h, conn := testHandler(t)
	u, _ := editUser(t, h, conn, "alice")
	dir := users.UserDir(h.cfg.UploadDir(), u.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blob.bin"), []byte{0x00, 0xff, 0x01}, 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, body := editOpen(t, h, u, "blob.bin")
	if code != http.StatusUnsupportedMediaType {
		t.Fatalf("binary edit = %d, want 415; body = %s", code, body)
	}
}

func TestEditRejectsTooLarge(t *testing.T) {
	h, conn := testHandler(t)
	u, dir := editUser(t, h, conn, "alice")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("a"), maxEditableBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, body := editOpen(t, h, u, "big.txt")
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large edit = %d, want 413; body = %s", code, body)
	}
}

func TestEditRejectsInvalidTargets(t *testing.T) {
	h, conn := testHandler(t)
	u, _ := editUser(t, h, conn, "alice")

	if code, _, _ := editOpen(t, h, u, "../escape.txt"); code != http.StatusBadRequest {
		t.Fatalf("traversal open = %d, want 400", code)
	}
	if code, _ := editSave(t, h, u, "../escape.txt", "x", "v", "lock"); code != http.StatusBadRequest {
		t.Fatalf("traversal save = %d, want 400", code)
	}
	if code, _, _ := editOpen(t, h, u, "missing.txt"); code != http.StatusNotFound {
		t.Fatalf("missing open = %d, want 404", code)
	}

	// A file deleted after it was opened: the lease is still valid but the
	// read must report missing.
	writeUserFile(t, h, u.ID, "gone.txt", "text")
	_, doc, _ := editOpen(t, h, u, "gone.txt")
	if err := os.Remove(filepath.Join(users.UserDir(h.cfg.UploadDir(), u.ID), "gone.txt")); err != nil {
		t.Fatal(err)
	}
	if code, _ := editSave(t, h, u, "gone.txt", "x", doc.Version, doc.Lock); code != http.StatusNotFound {
		t.Fatalf("save after external delete = %d, want 404", code)
	}
}

func TestEditRejectsMissingVersionAndBinaryContent(t *testing.T) {
	h, conn := testHandler(t)
	u, dir := editUser(t, h, conn, "alice")
	writeUserFile(t, h, u.ID, "notes.txt", "text")
	_, doc, _ := editOpen(t, h, u, "notes.txt")

	if code, _ := editSave(t, h, u, "notes.txt", "new", "", doc.Lock); code != http.StatusBadRequest {
		t.Fatalf("missing version = %d, want 400", code)
	}
	if code, _ := editSave(t, h, u, "notes.txt", string([]byte{0x00, 0xff}), doc.Version, doc.Lock); code != http.StatusUnsupportedMediaType {
		t.Fatalf("binary content = %d, want 415", code)
	}
	if got := readFile(t, filepath.Join(dir, "notes.txt")); got != "text" {
		t.Fatalf("file changed after rejected saves: %q", got)
	}
}

func TestListFilesEditable(t *testing.T) {
	h, conn := testHandler(t)
	u, dir := editUser(t, h, conn, "alice")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "text.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "binary.bin"), []byte{0x00, 0xff}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), bytes.Repeat([]byte("a"), maxEditableBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}

	req := withUser(httptest.NewRequest(http.MethodGet, "/dashboard/api/files", nil), u)
	rec := httptest.NewRecorder()
	h.ListFiles(rec, req)

	var resp struct {
		Files []fileInfo `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	byName := map[string]fileInfo{}
	for _, f := range resp.Files {
		byName[f.Name] = f
	}
	if !byName["text.txt"].Readable || !byName["text.txt"].Editable {
		t.Fatalf("text.txt flags = %+v", byName["text.txt"])
	}
	if byName["binary.bin"].Editable {
		t.Fatalf("binary.bin must not be editable: %+v", byName["binary.bin"])
	}
	if !byName["big.txt"].Readable || byName["big.txt"].Editable {
		t.Fatalf("big.txt flags = %+v", byName["big.txt"])
	}
}
