// Package filetype classifies files as text or binary by sniffing their
// leading bytes. It is used to decide which stored files may be read
// inline in the browser (always served as text/plain).
package filetype

import (
	"io"
	"os"
	"unicode/utf8"
)

const probeSize = 4096

// IsText reports whether the file at path looks like plain text. It opens
// the file and sniffs up to probeSize bytes: NUL bytes, invalid UTF-8, or
// an excess of control characters mark the file as binary.
func IsText(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, probeSize)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return false, err
	}
	return sampleIsText(buf[:n]), nil
}

// sampleIsText applies the text heuristic to a leading sample of a file.
// Empty samples are treated as text; anything containing NUL bytes, invalid
// UTF-8, or more than a small fraction of non-whitespace control characters
// is treated as binary.
func sampleIsText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if !utf8.Valid(b) {
		return false
	}
	controls := 0
	for _, c := range b {
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			controls++
		}
	}
	return float64(controls)/float64(len(b)) < 0.05
}
