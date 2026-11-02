// Package mnemonic generates human-memorable bearer tokens: five words drawn
// uniformly from the EFF large Diceware wordlist and joined with hyphens.
//
// Five words give about 64.6 bits of entropy (log2(7776^5)), which is far more
// than a typical human-chosen passphrase while staying readable and typeable.
//
// The wordlist is the EFF large wordlist (CC BY 3.0), with the four hyphenated
// entries replaced by hyphen-free synonyms so "-" is an unambiguous delimiter.
package mnemonic

import (
	"crypto/rand"
	_ "embed"
	"errors"
	"math/big"
	"strings"
)

// WordCount is the number of words in a generated phrase.
const WordCount = 5

//go:embed words.txt
var wordlist string

var words = strings.Fields(wordlist)

// Generate returns WordCount words joined by "-", selected uniformly with
// crypto/rand. Duplicate words are allowed; they are rare and do not break the
// format.
func Generate() (string, error) {
	if len(words) == 0 {
		return "", errors.New("mnemonic: empty wordlist")
	}
	limit := big.NewInt(int64(len(words)))
	picked := make([]string, WordCount)
	for i := range picked {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		picked[i] = words[n.Int64()]
	}
	return strings.Join(picked, "-"), nil
}

// WordlistSize reports how many distinct words the generator can choose from.
func WordlistSize() int { return len(words) }
