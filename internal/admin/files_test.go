package admin

import (
	"path/filepath"
	"testing"
)

func TestResolveStoredPathValid(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "uploads")
	ok := []string{
		"report.pdf",
		"report_abc123def456.pdf",
		"note.log",
		"sub.png",
		"a.b.txt",
		"..hidden",
	}
	for _, name := range ok {
		p, valid := resolveStoredPath(dir, name)
		if !valid {
			t.Errorf("resolveStoredPath(%q): expected valid", name)
			continue
		}
		if p != filepath.Join(dir, name) {
			t.Errorf("resolveStoredPath(%q) = %q, want %q", name, p, filepath.Join(dir, name))
		}
	}
}

func TestResolveStoredPathRejectsTraversal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "uploads")
	bad := []string{
		"",
		".",
		"..",
		"/",
		"/etc/passwd",
		"../etc/passwd",
		"../../../../etc/passwd",
		"a/../b",
		"a/../../b",
		"sub/dir/file.txt",
		"./file.txt",
		"..\\..\\windows\\win.ini",
		"/absolute",
		"../",
	}
	for _, name := range bad {
		if _, valid := resolveStoredPath(dir, name); valid {
			t.Errorf("resolveStoredPath(%q): expected rejected", name)
		}
	}
}

func TestResolveStoredPathRejectsControlBytes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "uploads")
	for _, name := range []string{"a\x00b.txt", "evil\r\n.txt", "tab\t.txt", "x\x7f"} {
		if _, valid := resolveStoredPath(dir, name); valid {
			t.Errorf("resolveStoredPath(%q): expected rejected", name)
		}
	}
}

func TestResolveStoredPathBackslashesRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "uploads")
	// Any separator (including Windows backslashes) is hostile input.
	if _, valid := resolveStoredPath(dir, `..\..\evil.txt`); valid {
		t.Fatal("expected backslash traversal to be rejected")
	}
}

func TestResolveStoredPathEmptyDir(t *testing.T) {
	if _, valid := resolveStoredPath("", "x.txt"); valid {
		t.Fatal("expected rejected when upload dir is empty")
	}
}

func TestHeaderFilename(t *testing.T) {
	if got := headerFilename(`a"b`); got != "ab" {
		t.Fatalf("quote not stripped: %q", got)
	}
	if got := headerFilename("a\r\nb"); got != "ab" {
		t.Fatalf("CRLF not stripped: %q", got)
	}
	if got := headerFilename(`a\b`); got != "ab" {
		t.Fatalf("backslash not stripped: %q", got)
	}
	if got := headerFilename("normal.txt"); got != "normal.txt" {
		t.Fatalf("normal name changed: %q", got)
	}
}
