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
//	printf 'root = "core";\nconfig authkey "k";\nconfig listen 13452;\nobject core {\n\tip "127.0.0.1";\n\ttype ping;\n\tdesc "core";\n};\n' \
//	  > /tmp/sysmon-hash-vector/sysmon.conf
//	sysmond -f /tmp/sysmon-hash-vector/sysmon.conf -d
//	AUTH k / CONFIG-GEN
//	  -> 333 0 e1668374...1299 1
//
// The file is identified by its name, not its path - which is what lets
// the same config hash the same as a seed in /etc and as the running copy
// in a generation directory.
const (
	vectorName = "sysmon.conf"
	vectorBody = "root = \"core\";\nconfig authkey \"k\";\nconfig listen 13452;\nobject core {\n\tip \"127.0.0.1\";\n\ttype ping;\n\tdesc \"core\";\n};\n"
	vectorHash = "e1668374fe84f9be431573c5c53bd1307808ea5f0e0028e6c8143fae7d4c1299"
)

func TestHashMatchesTheDaemon(t *testing.T) {
	got := HashFileSet([]string{vectorName}, [][]byte{[]byte(vectorBody)})
	if got != vectorHash {
		t.Errorf("this process and sysmond disagree about the config hash\n got  %s\n want %s",
			got, vectorHash)
	}
}

// The name is hashed, so renaming an include is a change - but the
// directory it is read from is not part of the name, which is what lets
// the same config hash identically as a seed in /etc and as the running
// copy in the generation directory.
func TestHashCoversTheName(t *testing.T) {
	a := HashFileSet([]string{"hosts.conf"}, [][]byte{[]byte("x")})
	b := HashFileSet([]string{"routers.conf"}, [][]byte{[]byte("x")})
	if a == b {
		t.Error("the same bytes under a different name hash the same")
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
	// Basenames: a config's identity cannot depend on which directory it
	// is being read out of, or a box would read as modified the moment its
	// running copy moved from /etc into the generation directory.
	want := HashFileSet([]string{"sysmon.conf", "hosts.conf"},
		[][]byte{[]byte(mainBody), []byte(incBody)})
	if got := d.Hash(); got != want {
		t.Errorf("Document.Hash() = %s, HashFileSet = %s", got, want)
	}
}
