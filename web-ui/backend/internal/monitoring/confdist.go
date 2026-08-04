package monitoring

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"sysmon-web/internal/config"
	"sysmon-web/internal/settings"
)

// Config distribution: the client half of sysmond's CONFIG-* commands.
//
// The daemon holds actual state - what is really on that box - and answers
// CONFIG-GEN with a generation number and a content hash every poll. This
// process holds desired state. Comparing the two is the whole conflict
// model, and it costs one line per site per cycle because the hash is
// computed on the box and never has to be transferred to be compared.
//
// Nothing is ever delivered to a box that has not been explicitly adopted.
// An unadopted box is a real state, not a missing value: its config shows
// read-only, and no sequence of clicks in this UI can blank a daemon whose
// config it has never seen.

// ConfigState is what an operator is shown per site.
type ConfigState string

const (
	// Nobody has adopted this box. Read-only; nothing is delivered.
	StateUnmanaged ConfigState = "unmanaged"
	// Running exactly what it should be.
	StateInSync ConfigState = "in-sync"
	// A newer generation exists here that the box does not have yet.
	StatePending ConfigState = "pending"
	// Right generation number, different bytes: somebody edited the box.
	StateModified ConfigState = "locally-modified"
	// The daemon refused the last delivery and is still running the one
	// before it.
	StateRejected ConfigState = "rejected"
	// The site is not answering, so none of the above is knowable.
	StateUnknown ConfigState = "unknown"
)

// SiteConfigStatus is the per-site row of the config page.
type SiteConfigStatus struct {
	Site              string      `json:"site"`
	Description       string      `json:"description,omitempty"`
	State             ConfigState `json:"state"`
	RunningGeneration uint64      `json:"running_generation"`
	RunningHash       string      `json:"running_hash,omitempty"`
	RunningFiles      int         `json:"running_files,omitempty"`
	DesiredGeneration uint64      `json:"desired_generation,omitempty"`
	DesiredHash       string      `json:"desired_hash,omitempty"`
	Adopted           bool        `json:"adopted"`
	Reachable         bool        `json:"reachable"`
	LastError         string      `json:"last_error,omitempty"`
	// LastDelivery is what the daemon said about the most recent PUT -
	// the parser's own words when it refused one.
	LastDelivery string `json:"last_delivery,omitempty"`
	Objects      int    `json:"objects,omitempty"`
	Poisoned     bool   `json:"poisoned,omitempty"`
}

// confState is the per-daemon half of distribution state, kept on the
// daemon record so it lives and dies with the connection.
type confState struct {
	mu sync.Mutex

	generation uint64
	hash       string
	files      int
	objects    int
	asked      time.Time
	lastErr    string
	lastReply  string
}

// ---------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------

// fetchConfigGen asks what the daemon is running. One line each way, on
// the connection the poller already has open and authenticated, so this is
// cheap enough to do every cycle - which is what makes "somebody edited
// this box" visible in seconds rather than whenever someone looks.
func (s *Service) fetchConfigGen(d *daemon, conn net.Conn, reader *bufio.Reader) {
	if _, err := conn.Write([]byte("CONFIG-GEN\n")); err != nil {
		d.conf.setErr("write failed: " + err.Error())
		return
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		d.conf.setErr("read failed: " + err.Error())
		return
	}
	trimmed := strings.TrimSpace(line)

	if !strings.HasPrefix(trimmed, "333") {
		// An older daemon, or one without the authkey. Either way there
		// is no config management here, and saying so beats showing a
		// box as permanently out of sync.
		d.conf.setErr(trimmed)
		return
	}

	fields := strings.Fields(trimmed)
	if len(fields) < 3 {
		d.conf.setErr("malformed CONFIG-GEN reply: " + trimmed)
		return
	}
	gen, _ := strconv.ParseUint(fields[1], 10, 64)
	files := 0
	if len(fields) >= 4 {
		files, _ = strconv.Atoi(fields[3])
	}

	d.conf.mu.Lock()
	d.conf.generation = gen
	d.conf.hash = fields[2]
	d.conf.files = files
	d.conf.asked = time.Now()
	d.conf.lastErr = ""
	d.conf.mu.Unlock()
}

func (c *confState) setErr(msg string) {
	c.mu.Lock()
	c.lastErr = msg
	c.hash = ""
	c.mu.Unlock()
}

func (c *confState) snapshot() (gen uint64, hash string, files int, lastErr, lastReply string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation, c.hash, c.files, c.lastErr, c.lastReply
}

// readUntilCode reads protocol lines until a three-digit response code,
// returning the code line and everything before it.
func readUntilCode(reader *bufio.Reader) (string, []string, error) {
	var body []string
	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		if len(trimmed) >= 3 && isDigits(trimmed[:3]) {
			return trimmed, body, nil
		}
		if trimmed != "" {
			body = append(body, trimmed)
		}
		if err != nil {
			return "", body, err
		}
	}
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// fetchConfigFiles pulls every config file the daemon is running.
//
// This is how a box is adopted: what becomes the first desired generation
// is what is really on the box, not something typed in and hoped to match.
func fetchConfigFiles(conn net.Conn, reader *bufio.Reader) ([]settings.GenFile, uint64, string, error) {
	if _, err := conn.Write([]byte("CONFIG-GET\n")); err != nil {
		return nil, 0, "", err
	}

	var (
		files   []settings.GenFile
		cur     *settings.GenFile
		b64     strings.Builder
		declare int
	)

	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")

		if len(trimmed) >= 3 && isDigits(trimmed[:3]) {
			if !strings.HasPrefix(trimmed, "333") {
				return nil, 0, "", fmt.Errorf("daemon refused CONFIG-GET: %s", trimmed)
			}
			fields := strings.Fields(trimmed)
			if len(fields) < 3 {
				return nil, 0, "", fmt.Errorf("malformed CONFIG-GET reply: %s", trimmed)
			}
			gen, _ := strconv.ParseUint(fields[1], 10, 64)
			return files, gen, fields[2], nil
		}

		switch {
		case strings.HasPrefix(trimmed, "FILE "):
			f := strings.Fields(trimmed)
			if len(f) < 3 {
				return nil, 0, "", fmt.Errorf("malformed FILE header: %s", trimmed)
			}
			path, derr := base64.StdEncoding.DecodeString(f[1])
			if derr != nil {
				return nil, 0, "", fmt.Errorf("undecodable path in %s: %w", trimmed, derr)
			}
			declare, _ = strconv.Atoi(f[2])
			cur = &settings.GenFile{Path: string(path)}
			b64.Reset()
		case trimmed == "ENDFILE":
			if cur == nil {
				return nil, 0, "", fmt.Errorf("ENDFILE with no FILE")
			}
			content, derr := base64.StdEncoding.DecodeString(b64.String())
			if derr != nil {
				return nil, 0, "", fmt.Errorf("undecodable content for %s: %w", cur.Path, derr)
			}
			if len(content) != declare {
				return nil, 0, "", fmt.Errorf("%s declared %d bytes but carried %d",
					cur.Path, declare, len(content))
			}
			cur.Content = content
			files = append(files, *cur)
			cur = nil
		default:
			if cur != nil {
				b64.WriteString(trimmed)
			}
		}

		if err != nil {
			return nil, 0, "", fmt.Errorf("connection closed mid-transfer: %w", err)
		}
	}
}

// putConfigFiles delivers a generation and waits for the daemon's verdict.
//
// The payload declares its own size so the daemon reads exactly that many
// bytes and stops - it never reads ahead into whatever command follows,
// and it never has to guess where the transfer ended.
func putConfigFiles(conn net.Conn, reader *bufio.Reader, gen uint64, files []settings.GenFile) (uint64, string, int, []string, error) {
	var payload strings.Builder
	for _, f := range files {
		fmt.Fprintf(&payload, "FILE %s %d\n",
			base64.StdEncoding.EncodeToString([]byte(f.Path)), len(f.Content))
		enc := base64.StdEncoding.EncodeToString(f.Content)
		for off := 0; off < len(enc); off += 960 {
			end := off + 960
			if end > len(enc) {
				end = len(enc)
			}
			payload.WriteString(enc[off:end])
			payload.WriteString("\n")
		}
		payload.WriteString("ENDFILE\n")
	}
	body := payload.String()

	if _, err := fmt.Fprintf(conn, "CONFIG-PUT %d %d\n", gen, len(body)); err != nil {
		return 0, "", 0, nil, err
	}
	if _, err := conn.Write([]byte(body)); err != nil {
		return 0, "", 0, nil, err
	}

	code, complaints, err := readUntilCode(reader)
	if err != nil {
		return 0, "", 0, complaints, fmt.Errorf("no verdict from the daemon: %w", err)
	}
	if !strings.HasPrefix(code, "333") {
		// The daemon's own parser said no. Its words go back up verbatim -
		// the operator needs to see what their daemon objected to, not a
		// summary written here.
		return 0, "", 0, complaints, fmt.Errorf("%s", code)
	}

	fields := strings.Fields(code)
	if len(fields) < 3 {
		return 0, "", 0, complaints, fmt.Errorf("malformed CONFIG-PUT reply: %s", code)
	}
	accepted, _ := strconv.ParseUint(fields[1], 10, 64)
	objects := 0
	if len(fields) >= 4 {
		objects, _ = strconv.Atoi(fields[3])
	}
	return accepted, fields[2], objects, complaints, nil
}

func rollbackConfig(conn net.Conn, reader *bufio.Reader) (uint64, string, []string, error) {
	if _, err := conn.Write([]byte("CONFIG-ROLLBACK\n")); err != nil {
		return 0, "", nil, err
	}
	code, complaints, err := readUntilCode(reader)
	if err != nil {
		return 0, "", complaints, err
	}
	if !strings.HasPrefix(code, "333") {
		return 0, "", complaints, fmt.Errorf("%s", code)
	}
	fields := strings.Fields(code)
	if len(fields) < 3 {
		return 0, "", complaints, fmt.Errorf("malformed rollback reply: %s", code)
	}
	gen, _ := strconv.ParseUint(fields[1], 10, 64)
	return gen, fields[2], complaints, nil
}

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

// ConfigStatus is the fleet's config state, one row per site.
func (s *Service) ConfigStatus() []SiteConfigStatus {
	store := s.Generations()
	var out []SiteConfigStatus

	for _, d := range s.fleet() {
		d.mu.Lock()
		site, desc, lastErr := d.site, d.siteDesc, d.lastErr
		d.mu.Unlock()
		if site == "" {
			site = "local"
		}

		gen, hash, files, confErr, lastReply := d.conf.snapshot()
		row := SiteConfigStatus{
			Site:              site,
			Description:       desc,
			RunningGeneration: gen,
			RunningHash:       hash,
			RunningFiles:      files,
			Reachable:         lastErr == "",
			LastError:         firstNonEmpty(lastErr, confErr),
			LastDelivery:      lastReply,
		}

		var desired settings.Desired
		haveDesired := false
		if store != nil {
			desired, haveDesired = store.GetDesired(site)
		}
		if haveDesired {
			row.DesiredGeneration = desired.Generation
			row.DesiredHash = desired.Hash
			row.Adopted = desired.Adopted
			_, row.Poisoned = desired.Poisoned[desired.Generation]
		}

		row.State = classify(row, haveDesired, hash != "")
		out = append(out, row)
	}
	return out
}

// classify turns the two sides' numbers into the state an operator reads.
//
// The ordering matters: "we cannot tell" has to win over every other
// answer, because reporting a box as in sync when it has not answered is
// the one failure that costs someone their weekend.
func classify(row SiteConfigStatus, haveDesired, heardFromBox bool) ConfigState {
	if !row.Reachable || !heardFromBox {
		return StateUnknown
	}
	if !haveDesired || !row.Adopted {
		return StateUnmanaged
	}
	switch {
	case row.RunningHash == row.DesiredHash:
		// The hash is the truth; the generation number is bookkeeping.
		// They can disagree legitimately - adopting a box records what it
		// already runs as generation 1 while the box still calls it 0 -
		// and a box running exactly the right bytes is in sync whatever
		// number either side has written down.
		return StateInSync
	case row.RunningGeneration < row.DesiredGeneration:
		return StatePending
	case row.RunningGeneration == row.DesiredGeneration:
		// Same generation number, different bytes: somebody edited the
		// box directly. Never resolved automatically - the person at the
		// console usually had a reason.
		return StateModified
	default:
		// The box claims a generation this process never issued. That is
		// what a rejected-then-rolled-back delivery looks like from here,
		// and also what a restored-from-backup box looks like.
		return StateRejected
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------

// daemonFor finds a site's daemon record.
func (s *Service) daemonFor(site string) *daemon {
	for _, d := range s.fleet() {
		d.mu.Lock()
		name := d.site
		d.mu.Unlock()
		if name == site || (name == "" && site == "local") {
			return d
		}
	}
	return nil
}

// withDaemonConn runs fn on an authenticated connection to a site.
//
// A dialled daemon gets a fresh socket, which keeps a long config transfer
// off the poller's connection entirely. A daemon that dialled us has only
// the one connection, so the poller is locked out for the duration - which
// is correct: a delivery is not something to interleave with a status
// fetch on the same socket.
func (s *Service) withDaemonConn(site string, fn func(net.Conn, *bufio.Reader) error) error {
	d := s.daemonFor(site)
	if d == nil {
		return fmt.Errorf("no site called %q is in the fleet", site)
	}

	key := s.authKey()
	if key == "" {
		return fmt.Errorf("config management needs sysmond's authkey, which is not configured here")
	}

	d.mu.Lock()
	inbound, conn, reader, addr := d.inbound, d.conn, d.reader, d.addr
	d.mu.Unlock()

	if inbound {
		if conn == nil {
			return fmt.Errorf("site %q is not connected", site)
		}
		// Hold the poller off this socket for the length of the exchange.
		d.confMu.Lock()
		defer d.confMu.Unlock()
		conn.SetDeadline(time.Now().Add(120 * time.Second))
		defer conn.SetDeadline(time.Time{})
		if err := authenticate(conn, reader, key); err != nil {
			return fmt.Errorf("authenticating to %s: %w", site, err)
		}
		return fn(conn, reader)
	}

	fresh, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dialling %s: %w", addr, err)
	}
	defer fresh.Close()
	fresh.SetDeadline(time.Now().Add(120 * time.Second))

	r := bufio.NewReader(fresh)
	if err := readWelcomeBanner(r); err != nil {
		return err
	}
	if err := authenticate(fresh, r, key); err != nil {
		return fmt.Errorf("authenticating to %s: %w", site, err)
	}
	return fn(fresh, r)
}

// AdoptSite takes what is really on the box and makes it the first desired
// generation.
//
// This is the only way a box becomes managed, and it is deliberately the
// same operation as recovering from "somebody fixed it on the console at
// 3am": pull up what is there, and agree that it is what should be there.
func (s *Service) AdoptSite(site, by string) (uint64, error) {
	store := s.Generations()
	if store == nil {
		return 0, fmt.Errorf("no settings store is attached")
	}

	var (
		files []settings.GenFile
		hash  string
	)
	err := s.withDaemonConn(site, func(conn net.Conn, r *bufio.Reader) error {
		var e error
		files, _, hash, e = fetchConfigFiles(conn, r)
		return e
	})
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		return 0, fmt.Errorf("%s returned no config files", site)
	}

	// Recompute rather than trust: if this process and the daemon ever
	// disagree about what the hash of a byte sequence is, the whole state
	// model is built on sand, and adoption is exactly where that has to
	// surface.
	paths := make([]string, len(files))
	contents := make([][]byte, len(files))
	for i, f := range files {
		paths[i], contents[i] = f.Path, f.Content
	}
	if mine := config.HashFileSet(paths, contents); mine != hash {
		return 0, fmt.Errorf("hash disagreement adopting %s: daemon says %s, we compute %s",
			site, hash, mine)
	}

	return store.PutGeneration(site, files, hash, by, "adopted from the box")
}

// DeliverSite pushes a site's desired generation to it.
func (s *Service) DeliverSite(site string) (*DeliveryResult, error) {
	store := s.Generations()
	if store == nil {
		return nil, fmt.Errorf("no settings store is attached")
	}

	desired, ok := store.GetDesired(site)
	if !ok || !desired.Adopted {
		return nil, fmt.Errorf("%s has not been adopted; nothing is delivered to a box "+
			"whose config has never been seen here", site)
	}
	if why, poisoned := desired.Poisoned[desired.Generation]; poisoned {
		return nil, fmt.Errorf("generation %d is poisoned: %s", desired.Generation, why)
	}
	files, ok := store.GetGenerationFiles(site, desired.Generation)
	if !ok {
		return nil, fmt.Errorf("generation %d of %s is not held here", desired.Generation, site)
	}

	res := &DeliveryResult{Site: site, Generation: desired.Generation}
	d := s.daemonFor(site)

	err := s.withDaemonConn(site, func(conn net.Conn, r *bufio.Reader) error {
		gen, hash, objects, complaints, e := putConfigFiles(conn, r, desired.Generation, files)
		res.Complaints = complaints
		if e != nil {
			return e
		}
		res.Accepted = true
		res.RunningGeneration = gen
		res.RunningHash = hash
		res.Objects = objects
		if hash != desired.Hash {
			// The bytes landed but do not hash to what we sent. Worth
			// shouting about: it means the two ends disagree about the
			// file set, not about the contents of one file.
			res.Warning = fmt.Sprintf(
				"delivered, but the box hashes to %s and we expected %s", hash, desired.Hash)
		}
		return nil
	})

	if d != nil {
		d.conf.mu.Lock()
		if err != nil {
			d.conf.lastReply = strings.Join(append(res.Complaints, err.Error()), "; ")
		} else {
			d.conf.lastReply = fmt.Sprintf("generation %d accepted, %d objects",
				res.RunningGeneration, res.Objects)
			d.conf.generation = res.RunningGeneration
			d.conf.hash = res.RunningHash
			d.conf.objects = res.Objects
		}
		d.conf.mu.Unlock()
	}
	return res, err
}

// DeliveryResult is what one box did with one generation.
type DeliveryResult struct {
	Site              string `json:"site"`
	Generation        uint64 `json:"generation"`
	Accepted          bool   `json:"accepted"`
	RunningGeneration uint64 `json:"running_generation,omitempty"`
	RunningHash       string `json:"running_hash,omitempty"`
	Objects           int    `json:"objects,omitempty"`
	Warning           string `json:"warning,omitempty"`
	// Complaints is what the daemon's own parser said, verbatim.
	Complaints []string `json:"complaints,omitempty"`
}

// RollbackSite tells a box to put its previous config back, and records
// that as the desired state.
//
// Recording it matters: without that, the next poll would see the box
// "behind" and the operator would be offered a redelivery of the config
// they just rolled away from.
func (s *Service) RollbackSite(site string) (*DeliveryResult, error) {
	res := &DeliveryResult{Site: site}

	err := s.withDaemonConn(site, func(conn net.Conn, r *bufio.Reader) error {
		gen, hash, complaints, e := rollbackConfig(conn, r)
		res.Complaints = complaints
		if e != nil {
			return e
		}
		res.Accepted = true
		res.RunningGeneration = gen
		res.RunningHash = hash
		return nil
	})
	if err != nil {
		return res, err
	}

	if store := s.Generations(); store != nil {
		store.SetDesiredGeneration(site, res.RunningGeneration, res.RunningHash)
	}
	if d := s.daemonFor(site); d != nil {
		d.conf.mu.Lock()
		d.conf.generation = res.RunningGeneration
		d.conf.hash = res.RunningHash
		d.conf.lastReply = fmt.Sprintf("rolled back to generation %d", res.RunningGeneration)
		d.conf.mu.Unlock()
	}
	return res, nil
}

// SiteConfigFiles returns what a box is running right now, for the editor
// and for the diff against desired state.
func (s *Service) SiteConfigFiles(site string) ([]settings.GenFile, uint64, string, error) {
	var (
		files []settings.GenFile
		gen   uint64
		hash  string
	)
	err := s.withDaemonConn(site, func(conn net.Conn, r *bufio.Reader) error {
		var e error
		files, gen, hash, e = fetchConfigFiles(conn, r)
		return e
	})
	return files, gen, hash, err
}

// StageGeneration records a new desired generation from an edited file set
// without delivering it. Delivery is a separate, deliberate act.
func (s *Service) StageGeneration(site string, files []settings.GenFile, by, note string) (uint64, string, error) {
	store := s.Generations()
	if store == nil {
		return 0, "", fmt.Errorf("no settings store is attached")
	}
	if len(files) == 0 {
		return 0, "", fmt.Errorf("a generation with no files would blank the box")
	}

	paths := make([]string, len(files))
	contents := make([][]byte, len(files))
	for i, f := range files {
		if f.Path == "" || !strings.HasPrefix(f.Path, "/") {
			return 0, "", fmt.Errorf("config file paths must be absolute; got %q", f.Path)
		}
		paths[i], contents[i] = f.Path, f.Content
	}
	hash := config.HashFileSet(paths, contents)

	gen, err := store.PutGeneration(site, files, hash, by, note)
	return gen, hash, err
}
