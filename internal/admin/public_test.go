package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/encrypt0r/ingestor/internal/db"
	"github.com/encrypt0r/ingestor/internal/identity"
	"github.com/encrypt0r/ingestor/internal/users"
)

func TestPublicSharesAreScopedPerUser(t *testing.T) {
	h, conn := testHandler(t)

	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := users.Create(conn, "bob", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}

	const name = "same.txt"
	for _, u := range []struct {
		id      int64
		content string
	}{{alice.ID, "alice-data"}, {bob.ID, "bob-data"}} {
		dir := users.UserDir(h.cfg.UploadDir(), u.id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(u.content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := db.MarkPublic(conn, u.id, name); err != nil {
			t.Fatal(err)
		}
	}

	get := func(rawQuery string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/pub?"+rawQuery, nil)
		rec := httptest.NewRecorder()
		h.PublicFile(rec, req)
		return rec.Code, rec.Body.String()
	}

	code, body := get("u=" + strconv.FormatInt(alice.ID, 10) + "&name=" + url.QueryEscape(name))
	if code != http.StatusOK || body != "alice-data" {
		t.Fatalf("alice share = %d %q", code, body)
	}
	code, body = get("u=" + strconv.FormatInt(bob.ID, 10) + "&name=" + url.QueryEscape(name))
	if code != http.StatusOK || body != "bob-data" {
		t.Fatalf("bob share = %d %q", code, body)
	}

	// The same stored name without an owner resolves to legacy storage (0),
	// so it must not leak either user's file.
	code, _ = get("name=" + url.QueryEscape(name))
	if code != http.StatusNotFound {
		t.Fatalf("ownerless share status = %d, want 404", code)
	}

	// Revoking one user's grant leaves the other user's identical name public.
	if err := db.MarkPrivate(conn, alice.ID, name); err != nil {
		t.Fatal(err)
	}
	code, _ = get("u=" + strconv.FormatInt(alice.ID, 10) + "&name=" + url.QueryEscape(name))
	if code != http.StatusNotFound {
		t.Fatalf("revoked alice share status = %d, want 404", code)
	}
	code, body = get("u=" + strconv.FormatInt(bob.ID, 10) + "&name=" + url.QueryEscape(name))
	if code != http.StatusOK || body != "bob-data" {
		t.Fatalf("bob share after alice revoke = %d %q", code, body)
	}
}

func TestDeleteRevokesPublicGrant(t *testing.T) {
	h, conn := testHandler(t)
	alice, err := users.Create(conn, "alice", "strong-password-123", 0)
	if err != nil {
		t.Fatal(err)
	}

	const name = "revoke.txt"
	dir := users.UserDir(h.cfg.UploadDir(), alice.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkPublic(conn, alice.ID, name); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/dashboard/delete", strings.NewReader("name="+url.QueryEscape(name)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withUser(req, identity.User{ID: alice.ID, Username: "alice", Role: identity.RoleUser})
	rec := httptest.NewRecorder()
	h.Delete(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if db.IsPublic(conn, alice.ID, name) {
		t.Fatal("deleting a file must revoke its public grant")
	}
}
