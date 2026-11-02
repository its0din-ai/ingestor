package admin

import (
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

	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/users"
)

// doRename calls the handler as the given user.
func doRename(t *testing.T, h *Handler, u identity.User, from, to string) (int, string) {
	t.Helper()
	form := url.Values{"name": {from}, "to": {to}}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/rename", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, u)
	rec := httptest.NewRecorder()
	h.Rename(rec, req)
	return rec.Code, rec.Body.String()
}

func writeUserFile(t *testing.T, h *Handler, userID int64, name, content string) string {
	t.Helper()
	dir := users.UserDir(h.cfg.UploadDir(), userID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s should not exist (stat err = %v)", path, err)
	}
}

func TestRenameFile(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)

	writeUserFile(t, h, alice.ID, "report.pdf", "payload")

	code, body := doRename(t, h, u, "report.pdf", "final.pdf")
	if code != http.StatusOK {
		t.Fatalf("rename status = %d, body = %s", code, body)
	}
	mustNotExist(t, filepath.Join(dir, "report.pdf"))
	if got := readFile(t, filepath.Join(dir, "final.pdf")); got != "payload" {
		t.Fatalf("renamed content = %q, want payload", got)
	}
}

func TestRenameRejectsInvalidNames(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}
	writeUserFile(t, h, alice.ID, "keep.txt", "x")

	bad := []string{
		"",
		"   ",
		".",
		"..",
		"../escape.txt",
		"sub/dir.txt",
		`..\..\escape.txt`,
		"a\x00b.txt",
		"line\nbreak.txt",
		strings.Repeat("a", maxStoredNameBytes+1),
	}
	for _, to := range bad {
		code, body := doRename(t, h, u, "keep.txt", to)
		if code != http.StatusBadRequest {
			t.Errorf("rename to %q = %d, want 400 (body = %s)", to, code, body)
		}
	}

	// The source is still intact after every rejected attempt.
	if got := readFile(t, filepath.Join(users.UserDir(h.cfg.UploadDir(), alice.ID), "keep.txt")); got != "x" {
		t.Fatalf("source changed after rejected renames: %q", got)
	}
}

func TestRenameMissingSource(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}

	code, body := doRename(t, h, u, "does-not-exist.txt", "new.txt")
	if code != http.StatusNotFound {
		t.Fatalf("rename missing source = %d, want 404 (body = %s)", code, body)
	}
}

func TestRenameRefusesToOverwrite(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)
	writeUserFile(t, h, alice.ID, "source.txt", "source-data")
	writeUserFile(t, h, alice.ID, "taken.txt", "taken-data")

	code, body := doRename(t, h, u, "source.txt", "taken.txt")
	if code != http.StatusConflict {
		t.Fatalf("rename onto existing file = %d, want 409 (body = %s)", code, body)
	}
	if got := readFile(t, filepath.Join(dir, "source.txt")); got != "source-data" {
		t.Fatalf("source content changed: %q", got)
	}
	if got := readFile(t, filepath.Join(dir, "taken.txt")); got != "taken-data" {
		t.Fatalf("target was overwritten: %q", got)
	}
}

func TestRenamePreservesQuarantine(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)
	writeUserFile(t, h, alice.ID, "evil.exe.quarantined", "binary")

	code, body := doRename(t, h, u, "evil.exe.quarantined", "safe.exe")
	if code != http.StatusOK {
		t.Fatalf("rename quarantined file = %d, body = %s", code, body)
	}
	mustNotExist(t, filepath.Join(dir, "evil.exe.quarantined"))
	if got := readFile(t, filepath.Join(dir, "safe.exe.quarantined")); got != "binary" {
		t.Fatalf("quarantined content = %q", got)
	}
	// Renaming never releases a quarantined file.
	mustNotExist(t, filepath.Join(dir, "safe.exe"))

	// A plain file cannot be renamed to look quarantined.
	writeUserFile(t, h, alice.ID, "plain.txt", "text")
	code, body = doRename(t, h, u, "plain.txt", "spoof.quarantined")
	if code != http.StatusOK {
		t.Fatalf("rename plain file = %d, body = %s", code, body)
	}
	if got := readFile(t, filepath.Join(dir, "spoof")); got != "text" {
		t.Fatalf("spoof content = %q", got)
	}
	mustNotExist(t, filepath.Join(dir, "spoof.quarantined"))
}

func TestRenameMovesHistoryAndPublicGrant(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}
	writeUserFile(t, h, alice.ID, "orig.txt", "data")

	if err := db.InsertUpload(conn, db.UploadRecord{
		UserID:       alice.ID,
		OriginalName: "orig.txt",
		StoredName:   "orig.txt",
		FileSize:     4,
		RemoteAddr:   "203.0.113.9",
		Source:       "browser",
		CreatedAt:    time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkPublic(conn, alice.ID, "orig.txt"); err != nil {
		t.Fatal(err)
	}

	code, body := doRename(t, h, u, "orig.txt", "renamed.txt")
	if code != http.StatusOK {
		t.Fatalf("rename = %d, body = %s", code, body)
	}

	if ip, _ := db.UploaderIP(conn, alice.ID, "renamed.txt"); ip != "203.0.113.9" {
		t.Fatalf("uploader IP after rename = %q", ip)
	}
	if src, _ := db.UploadSource(conn, alice.ID, "renamed.txt"); src != "browser" {
		t.Fatalf("source after rename = %q", src)
	}
	if !db.IsPublic(conn, alice.ID, "renamed.txt") {
		t.Fatal("public grant did not follow the rename")
	}
	if db.IsPublic(conn, alice.ID, "orig.txt") {
		t.Fatal("stale public grant left under the old name")
	}
}

// TestRenameConcurrentSameSource races several renames of one file to
// different targets. Exactly one must win; every loser must leave no trace.
func TestRenameConcurrentSameSource(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)
	writeUserFile(t, h, alice.ID, "race.txt", "payload")

	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i], _ = doRename(t, h, u, "race.txt", fmt.Sprintf("target-%d.txt", i))
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i, code := range codes {
		switch code {
		case http.StatusOK:
			wins++
		case http.StatusNotFound, http.StatusConflict:
			// Lost the race; acceptable.
		default:
			t.Errorf("rename %d returned unexpected status %d", i, code)
		}
	}
	if wins != 1 {
		t.Fatalf("%d renames succeeded, want exactly 1 (codes = %v)", wins, codes)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory has %d files after race (%v), want exactly 1", len(entries), names)
	}
	if got := readFile(t, filepath.Join(dir, entries[0].Name())); got != "payload" {
		t.Fatalf("surviving content = %q, want payload", got)
	}
}

// TestRenameConcurrentSameTarget races renames of one file onto the same
// destination. One wins and the destination is never corrupted or duplicated.
func TestRenameConcurrentSameTarget(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)
	writeUserFile(t, h, alice.ID, "race.txt", "payload")

	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i], _ = doRename(t, h, u, "race.txt", "dest.txt")
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i, code := range codes {
		switch code {
		case http.StatusOK:
			wins++
		case http.StatusNotFound, http.StatusConflict:
		default:
			t.Errorf("rename %d returned unexpected status %d", i, code)
		}
	}
	if wins != 1 {
		t.Fatalf("%d renames succeeded, want exactly 1 (codes = %v)", wins, codes)
	}
	if got := readFile(t, filepath.Join(dir, "dest.txt")); got != "payload" {
		t.Fatalf("destination content = %q, want payload", got)
	}
	mustNotExist(t, filepath.Join(dir, "race.txt"))
}

// TestRenameConcurrentDifferentSourcesSameTarget races two different files
// onto one destination name. The loser must keep its source file, so no data
// is lost to a silent overwrite.
func TestRenameConcurrentDifferentSourcesSameTarget(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	u := identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser}
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)
	writeUserFile(t, h, alice.ID, "a.txt", "AAA")
	writeUserFile(t, h, alice.ID, "b.txt", "BBB")

	type result struct {
		from string
		code int
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, from := range []string{"a.txt", "b.txt"} {
		wg.Add(1)
		go func(i int, from string) {
			defer wg.Done()
			<-start
			code, _ := doRename(t, h, u, from, "dest.txt")
			results[i] = result{from: from, code: code}
		}(i, from)
	}
	close(start)
	wg.Wait()

	wins, conflicts := 0, 0
	for _, r := range results {
		switch r.code {
		case http.StatusOK:
			wins++
		case http.StatusConflict:
			conflicts++
		default:
			t.Errorf("rename %s returned unexpected status %d", r.from, r.code)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("wins = %d, conflicts = %d; want 1 and 1 (%+v)", wins, conflicts, results)
	}

	// The destination holds one payload and the losing source still holds the
	// other: neither file's bytes were destroyed.
	dest := readFile(t, filepath.Join(dir, "dest.txt"))
	if dest != "AAA" && dest != "BBB" {
		t.Fatalf("destination content = %q", dest)
	}
	loser := "a.txt"
	if dest == "AAA" {
		loser = "b.txt"
	}
	if got := readFile(t, filepath.Join(dir, loser)); got == dest {
		t.Fatalf("loser source content %q was overwritten", got)
	}
}
