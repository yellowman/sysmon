package config

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// HashFileSet is the content hash both ends of the fleet compare.
//
// It must agree bit-for-bit with confgen_hash() in src/confgen.c, because
// disagreeing means every box reads as "locally modified" forever and the
// state stops meaning anything. The definition, for each file in load
// order: the name's length, the name, the content's length, the content -
// lengths as 8 bytes big-endian so no two file sets can produce the same
// stream.
//
// Names, not paths. The same config has to hash the same whether the box
// is reading it as a seed from /etc or as the running copy out of its
// generation directory; if it did not, adopting a box and delivering its
// own bytes straight back would read as a change forever.
//
// Bytes are hashed exactly as they are. Nothing is normalised, no
// whitespace is touched, no line endings are translated. That is what
// makes an untouched config hash identically forever, and it is only
// achievable because edits splice rather than regenerate.
func HashFileSet(names []string, contents [][]byte) string {
	h := sha256.New()
	var n [8]byte

	for i, p := range names {
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write([]byte(p))

		var body []byte
		if i < len(contents) {
			body = contents[i]
		}
		binary.BigEndian.PutUint64(n[:], uint64(len(body)))
		h.Write(n[:])
		h.Write(body)
	}
	return hex.EncodeToString(h.Sum(nil))
}
