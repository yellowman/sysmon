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
// order: the path's length, the path, the content's length, the content -
// lengths as 8 bytes big-endian so no two file sets can produce the same
// stream.
//
// Bytes are hashed exactly as they are. Nothing is normalised, no
// whitespace is touched, no line endings are translated. That is what
// makes an untouched config hash identically forever, and it is only
// achievable because edits splice rather than regenerate.
func HashFileSet(paths []string, contents [][]byte) string {
	h := sha256.New()
	var n [8]byte

	for i, p := range paths {
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
