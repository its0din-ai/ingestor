package filetype

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSampleIsText(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", []byte{}, true},
		{"ascii text", []byte("hello world\nsecond line\r\n"), true},
		{"json", []byte("{\"a\":1,\"b\":[true,null]}\n"), true},
		{"markdown", []byte("# Title\n\nSome **bold** and `code`.\n"), true},
		{"html", []byte("<!DOCTYPE html><html><body>hi</body></html>\n"), true},
		{"utf8 text", []byte("héllo wörld — café\n"), true},
		{"nul bytes", []byte("AB\x00CD\x00EF"), false},
		{"invalid utf8", []byte("foo\xff\xfe bar"), false},
		{"control heavy", []byte("a\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e"), false},
		{"binary-ish", []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}, false},
		{"pdf header", []byte("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"), false},
		{"just whitespace", []byte("\t\n \n\r\n"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sampleIsText(tt.data); got != tt.want {
				t.Errorf("sampleIsText(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestIsTextFile(t *testing.T) {
	dir := t.TempDir()
	txt := filepath.Join(dir, "note.log")
	bin := filepath.Join(dir, "data.bin")

	if err := os.WriteFile(txt, []byte("line one\nline two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00}, 0o644); err != nil {
		t.Fatal(err)
	}

	if got, err := IsText(txt); err != nil || !got {
		t.Fatalf("IsText(%s) = %v, %v; want true, nil", txt, got, err)
	}
	if got, err := IsText(bin); err != nil || got {
		t.Fatalf("IsText(%s) = %v, %v; want false, nil", bin, got, err)
	}
	if _, err := IsText(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("IsText on missing file: expected error, got nil")
	}
}
