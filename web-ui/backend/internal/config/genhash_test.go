package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The hash is the whole conflict model: the daemon computes it over its
// own files and this process computes it over what it thinks those files
// should be, and the two are compared without transferring anything. If
// they ever disagree, every box in the fleet reads as "locally modified"
// forever - so the agreement is pinned to a vector taken from a real
// sysmond rather than to this implementation's own opinion.
//
// Vector produced by:
//
//	mkdir /tmp/sysmon-hash-vector
//	printf 'root = "core";\nconfig authkey "k";\nobject core {\n\tip "127.0.0.1";\n\ttype ping;\n\tdesc "core";\n};\n' \
//	  > /tmp/sysmon-hash-vector/sysmon.conf
//	sysmond -f /tmp/sysmon-hash-vector/sysmon.conf -p 13452 -d
//	AUTH k / CONFIG-GEN
//	  -> 333 0 f2114b41...87db 1
//
// Note the path is part of the hash, so the vector carries the path it was
// computed at.
const (
	vectorPath = "/tmp/sysmon-hash-vector/sysmon.conf"
	vectorBody = "root = \"core\";\nconfig authkey \"k\";\nobject core {\n\tip \"127.0.0.1\";\n\ttype ping;\n\tdesc \"core\";\n};\n"
	vectorHash = "f2114b41671929d8fc67b5b4486535210d1013fcd84bfc1ede8aafcb7baf87db"
)

func TestHashMatchesTheDaemon(t *testing.T) {
	got := HashFileSet([]string{vectorPath}, [][]byte{[]byte(vectorBody)})
	if got != vectorHash {
		t.Errorf("this process and sysmond disagree about the config hash\n got  %s\n want %s",
			got, vectorHash)
	}
}

// The path is hashed, not just the content: two boxes running identical
// bytes at different paths are not running the same config, because a
// delivery names paths.
func TestHashCoversThePath(t *testing.T) {
	a := HashFileSet([]string{"/etc/sysmon.conf"}, [][]byte{[]byte("x")})
	b := HashFileSet([]string{"/usr/local/etc/sysmon.conf"}, [][]byte{[]byte("x")})
	if a == b {
		t.Error("the same bytes at a different path hash the same")
	}
}

// Length prefixes exist so no two file sets can produce the same stream.
// Without them "ab"+"c" and "a"+"bc" would be indistinguishable.
func TestHashCannotBeFooledByMovingAByte(t *testing.T) {
	a := HashFileSet([]string{"/a", "/b"}, [][]byte{[]byte("AB"), []byte("C")})
	b := HashFileSet([]string{"/a", "/b"}, [][]byte{[]byte("A"), []byte("BC")})
	if a == b {
		t.Error("moving a byte between files did not change the hash")
	}
}

// A Document hashes exactly as a bare file set does, since the two are
// compared against each other constantly.
func TestDocumentHashAgreesWithFileSet(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sysmon.conf")
	inc := filepath.Join(dir, "hosts.conf")

	mainBody := "root = \"core\";\ninclude \"hosts.conf\";\nobject core {\n\tip \"1.1.1.1\";\n\ttype ping;\n};\n"
	incBody := "# hosts\nobject leaf {\n\tip \"1.1.1.2\";\n\ttype ping;\n\tdep \"core\";\n};\n"
	if err := os.WriteFile(main, []byte(mainBody), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inc, []byte(incBody), 0644); err != nil {
		t.Fatal(err)
	}

	d, err := LoadDocument(main)
	if err != nil {
		t.Fatal(err)
	}
	want := HashFileSet([]string{main, inc}, [][]byte{[]byte(mainBody), []byte(incBody)})
	if got := d.Hash(); got != want {
		t.Errorf("Document.Hash() = %s, HashFileSet = %s", got, want)
	}
}
