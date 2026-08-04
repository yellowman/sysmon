package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"sysmon-web/internal/models"
)

// Editing a config by regenerating it from the parsed model throws away
// everything the model does not carry: comments, hand-formatting, and -
// worse - the `include` directives themselves, since the parser follows
// includes but the generator has no notion of them. Saving a config with
// includes through the editor flattened every included object into the
// main file and dropped the includes entirely.
//
// A Document is the fix. It holds every file of a config as bytes, with the
// byte range of each object recorded, so an edit replaces exactly the bytes
// of the objects that changed and touches nothing else. Comments survive
// because nothing goes near them; includes survive because an object is
// edited in the file it actually lives in; and an untouched config comes
// back byte-identical, which is what makes content hashing usable for
// fleet management.

// Span is where an object lives: which file, and which bytes of it.
type Span struct {
	File  string // path of the file the object is written in
	Start int    // byte offset of the 'o' in "object"
	End   int    // byte offset just past the closing "};"
}

// Document is a config file and everything it includes, kept as text.
type Document struct {
	MainPath string
	Order    []string          // load order, main file first
	Files    map[string][]byte // path -> current content
	Objects  map[string]Span   // object name -> where it is written

	dirty map[string]bool
}

// LoadDocument reads a config and every file it includes, recording where
// each object is written.
func LoadDocument(path string) (*Document, error) {
	d := &Document{
		MainPath: path,
		Files:    make(map[string][]byte),
		Objects:  make(map[string]Span),
		dirty:    make(map[string]bool),
	}
	if err := d.load(path, 0); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Document) load(path string, depth int) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("include depth exceeded at %s", path)
	}
	if _, seen := d.Files[path]; seen {
		return nil // an include cycle is the config's problem, not ours
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	d.Files[path] = content
	d.Order = append(d.Order, path)

	for _, obj := range scanObjects(content) {
		obj.File = path
		name := objectName(content[obj.Start:obj.End])
		if name == "" {
			continue
		}
		// First definition wins, which is what sysmond does with a
		// duplicate name.
		if _, dup := d.Objects[name]; !dup {
			d.Objects[name] = obj
		}
	}

	for _, inc := range scanIncludes(content) {
		p := inc
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(path), p)
		}
		if err := d.load(p, depth+1); err != nil {
			// A missing include is a config error, not a reason to
			// refuse to show the operator the rest of the file.
			continue
		}
	}
	return nil
}

// scanObjects finds every "object NAME { ... };" block, skipping comments
// and quoted strings so a brace or a '#' inside either cannot confuse it.
func scanObjects(b []byte) []Span {
	var out []Span
	i := 0
	n := len(b)

	for i < n {
		switch {
		case b[i] == '#':
			for i < n && b[i] != '\n' {
				i++
			}
		case b[i] == '"':
			i++
			for i < n && b[i] != '"' {
				i++
			}
			i++
		case isWordStart(b, i, "object"):
			start := i
			i += len("object")
			// name, then the opening brace
			for i < n && b[i] != '{' && b[i] != '\n' {
				i++
			}
			if i >= n || b[i] != '{' {
				continue // not an object block after all
			}
			depth := 0
			for i < n {
				if b[i] == '#' {
					for i < n && b[i] != '\n' {
						i++
					}
					continue
				}
				if b[i] == '"' {
					i++
					for i < n && b[i] != '"' {
						i++
					}
					i++
					continue
				}
				if b[i] == '{' {
					depth++
				} else if b[i] == '}' {
					depth--
					if depth == 0 {
						i++
						// swallow the terminating semicolon
						for i < n && (b[i] == ' ' || b[i] == '\t') {
							i++
						}
						if i < n && b[i] == ';' {
							i++
						}
						out = append(out, Span{Start: start, End: i})
						break
					}
				}
				i++
			}
		default:
			i++
		}
	}
	return out
}

// scanIncludes finds include directives, outside comments and strings.
func scanIncludes(b []byte) []string {
	var out []string
	i := 0
	n := len(b)

	for i < n {
		switch {
		case b[i] == '#':
			for i < n && b[i] != '\n' {
				i++
			}
		case isWordStart(b, i, "include"):
			i += len("include")
			for i < n && b[i] != '\n' && b[i] != ';' {
				if b[i] == '"' {
					i++
					start := i
					for i < n && b[i] != '"' {
						i++
					}
					out = append(out, string(b[start:i]))
					break
				}
				i++
			}
		default:
			i++
		}
	}
	return out
}

// isWordStart reports whether word starts at i on a token boundary.
func isWordStart(b []byte, i int, word string) bool {
	if i+len(word) > len(b) {
		return false
	}
	if string(b[i:i+len(word)]) != word {
		return false
	}
	if i > 0 && !isSep(b[i-1]) {
		return false
	}
	if i+len(word) < len(b) && !isSep(b[i+len(word)]) {
		return false
	}
	return true
}

func isSep(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ';' || c == '}' || c == '{'
}

// objectName pulls NAME out of "object NAME {".
func objectName(block []byte) string {
	s := string(block)
	s = strings.TrimPrefix(s, "object")
	if i := strings.IndexByte(s, '{'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// ReplaceObject rewrites one object in place, leaving every other byte of
// the file - comments included - exactly as it was.
func (d *Document) ReplaceObject(name, text string) bool {
	span, ok := d.Objects[name]
	if !ok {
		return false
	}
	content := d.Files[span.File]

	text = strings.TrimRight(text, "\n")
	updated := make([]byte, 0, len(content)+len(text))
	updated = append(updated, content[:span.Start]...)
	updated = append(updated, text...)
	updated = append(updated, content[span.End:]...)

	d.Files[span.File] = updated
	d.dirty[span.File] = true
	d.reindex(span.File)
	return true
}

// AddObject appends a new object to the main file.
func (d *Document) AddObject(name, text string) {
	content := d.Files[d.MainPath]
	if len(content) > 0 && content[len(content)-1] != '\n' {
		content = append(content, '\n')
	}
	text = strings.TrimRight(text, "\n")
	content = append(content, '\n')
	content = append(content, text...)
	content = append(content, '\n')

	d.Files[d.MainPath] = content
	d.dirty[d.MainPath] = true
	d.reindex(d.MainPath)
}

// DeleteObject removes an object and the blank line that followed it,
// leaving any comment that preceded it alone - a comment above a deleted
// object is usually about the section, not the object.
func (d *Document) DeleteObject(name string) bool {
	span, ok := d.Objects[name]
	if !ok {
		return false
	}
	content := d.Files[span.File]

	end := span.End
	for end < len(content) && (content[end] == ' ' || content[end] == '\t') {
		end++
	}
	if end < len(content) && content[end] == '\n' {
		end++
	}
	if end < len(content) && content[end] == '\n' {
		end++
	}

	updated := make([]byte, 0, len(content))
	updated = append(updated, content[:span.Start]...)
	updated = append(updated, content[end:]...)

	d.Files[span.File] = updated
	d.dirty[span.File] = true
	d.reindex(span.File)
	return true
}

// reindex re-scans one file after an edit shifts its offsets.
func (d *Document) reindex(path string) {
	for name, span := range d.Objects {
		if span.File == path {
			delete(d.Objects, name)
		}
	}
	content := d.Files[path]
	for _, obj := range scanObjects(content) {
		obj.File = path
		name := objectName(content[obj.Start:obj.End])
		if name == "" {
			continue
		}
		if _, dup := d.Objects[name]; !dup {
			d.Objects[name] = obj
		}
	}
}

// Dirty lists the files an edit actually changed.
func (d *Document) Dirty() []string {
	var out []string
	for _, p := range d.Order {
		if d.dirty[p] {
			out = append(out, p)
		}
	}
	return out
}

// Hash is the content hash of the whole config: main file then each
// include in load order, each contribution length-prefixed so no
// concatenation can be ambiguous. Bytes are hashed as they are - never
// normalised - so an untouched config hashes identically forever, which is
// what lets a fleet tell "in sync" from "somebody edited this box".
func (d *Document) Hash() string {
	contents := make([][]byte, len(d.Order))
	for i, p := range d.Order {
		contents[i] = d.Files[p]
	}
	// One implementation, shared with the fleet: HashFileSet is what the
	// daemon's confgen_hash() has to agree with byte for byte, and a
	// second copy of the rule here is a second chance to drift from it.
	return HashFileSet(d.Order, contents)
}

// Apply edits the document so its objects match cfg, touching only what
// differs. Returns the number of objects added, changed and removed.
//
// This is the whole point: the incoming model has no idea comments exist,
// but it does not need to - an object nobody edited is not rewritten, and
// one that was edited is replaced a block at a time.
func (d *Document) Apply(cfg *models.Config) (added, changed, removed int) {
	if cfg == nil {
		return 0, 0, 0
	}

	// Keep the caller's order. Walking a map instead would append new
	// objects in whatever order Go felt like that run, so two saves of
	// the same config could produce different bytes - and therefore
	// different hashes, which is what fleet management compares.
	wanted := make(map[string]models.Host, len(cfg.Hosts))
	order := make([]string, 0, len(cfg.Hosts))
	for _, h := range cfg.Hosts {
		name := h.Hostname
		if name == "" {
			name = h.ID
		}
		if name == "" {
			continue
		}
		if _, dup := wanted[name]; !dup {
			order = append(order, name)
		}
		wanted[name] = h
	}

	for _, name := range order {
		h := wanted[name]
		span, exists := d.Objects[name]
		if !exists {
			d.AddObject(name, GenerateHost(h))
			added++
			continue
		}
		// Compare meaning, not text. A hand-written object almost never
		// matches the generator byte for byte - different field order,
		// different spacing, a comment inside the block - and rewriting
		// all of them on every save would destroy exactly the
		// hand-formatting this exists to protect. So an object is only
		// replaced when what it *says* has changed.
		if onDisk, ok := d.hostAt(span); ok && sameHost(onDisk, h) {
			continue
		}
		d.ReplaceObject(name, GenerateHost(h))
		changed++
	}

	// Collect first, then delete. DeleteObject reindexes the file it
	// touched, which deletes and re-adds every entry that file owns -
	// mutating the map mid-range, so deleting two objects from one file
	// could silently skip one of them.
	var doomed []string
	for name := range d.Objects {
		if _, keep := wanted[name]; !keep {
			doomed = append(doomed, name)
		}
	}
	sort.Strings(doomed)
	for _, name := range doomed {
		if d.DeleteObject(name) {
			removed++
		}
	}

	return added, changed, removed
}

// hostAt parses the object block a span covers back into the model, so it
// can be compared with what the editor is asking for.
func (d *Document) hostAt(span Span) (models.Host, bool) {
	block := d.Files[span.File][span.Start:span.End]
	cfg, err := Parse(block)
	if err != nil || cfg == nil || len(cfg.Hosts) != 1 {
		return models.Host{}, false
	}
	return cfg.Hosts[0], true
}

// sameHost reports whether two objects mean the same thing. ID is ignored:
// it is derived from the name, not something an operator sets.
func sameHost(a, b models.Host) bool {
	a.ID, b.ID = "", ""
	return reflect.DeepEqual(a, b)
}

// Save writes back only the files an edit touched.
func (d *Document) Save() error {
	for _, p := range d.Dirty() {
		info, err := os.Stat(p)
		mode := os.FileMode(0644)
		if err == nil {
			mode = info.Mode()
		}
		// Write-then-rename so a crash mid-save cannot leave a daemon
		// with half a config.
		tmp := p + ".sysmon-web.tmp"
		if err := os.WriteFile(tmp, d.Files[p], mode); err != nil {
			return fmt.Errorf("write %s: %w", tmp, err)
		}
		if err := os.Rename(tmp, p); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("replace %s: %w", p, err)
		}
	}
	return nil
}
