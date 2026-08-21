package diskusage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUploadDirSumsFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.log"), make([]byte, 40), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := UploadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != 140 {
		t.Fatalf("UploadDir = %d, want 140", got)
	}
}

func TestUploadDirMissingDirIsZero(t *testing.T) {
	got, err := UploadDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("expected no error for missing dir, got %v", err)
	}
	if got != 0 {
		t.Fatalf("UploadDir(missing) = %d, want 0", got)
	}
}

func TestSummary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.txt"), make([]byte, 10), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := Summary(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.UploadDirBytes != 10 {
		t.Fatalf("UploadDirBytes = %d, want 10", info.UploadDirBytes)
	}
	if info.TotalBytes <= 0 || info.FreeBytes <= 0 {
		t.Fatalf("unexpected fs stats: %+v", info)
	}
	if pct := FreePercent(info); pct <= 0 || pct > 100 {
		t.Fatalf("FreePercent = %v, want in (0,100]", pct)
	}
}

func TestSummaryFallsBackOnMissingDir(t *testing.T) {
	if _, err := Summary(filepath.Join(t.TempDir(), "nope")); err != nil {
		t.Fatalf("expected no error (falls back to cwd), got %v", err)
	}
}
