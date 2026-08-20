package upload

import (
	"strings"
	"testing"
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
