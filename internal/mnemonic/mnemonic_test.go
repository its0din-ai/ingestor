package mnemonic

import (
	"strings"
	"testing"
)

func TestGenerateFormat(t *testing.T) {
	set := wordSet()
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		phrase, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(phrase, "-")
		if len(parts) != WordCount {
			t.Fatalf("phrase %q has %d parts, want %d", phrase, len(parts), WordCount)
		}
		for _, w := range parts {
			if w == "" || !set[w] {
				t.Fatalf("phrase %q contains unknown word %q", phrase, w)
			}
		}
		seen[phrase] = true
	}
	// Randomness sanity check: 1000 draws from ~64 bits must not all be equal.
	if len(seen) < 990 {
		t.Fatalf("only %d distinct phrases in 1000 draws", len(seen))
	}
}

func TestWordlist(t *testing.T) {
	if got := WordlistSize(); got != 7776 {
		t.Fatalf("wordlist size = %d, want 7776", got)
	}
	set := wordSet()
	if len(set) != WordlistSize() {
		t.Fatalf("wordlist contains duplicates: %d unique of %d", len(set), WordlistSize())
	}
	for _, w := range words {
		if strings.ContainsAny(w, "- \t\r\n") {
			t.Fatalf("bad word %q in wordlist", w)
		}
		for _, r := range w {
			if r < 'a' || r > 'z' {
				t.Fatalf("word %q contains non-lowercase-letter %q", w, r)
			}
		}
	}
}

func wordSet() map[string]bool {
	set := make(map[string]bool, len(words))
	for _, w := range words {
		set[w] = true
	}
	return set
}
