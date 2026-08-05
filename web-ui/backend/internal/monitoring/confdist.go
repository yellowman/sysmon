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
	// Unmanageable is the daemon's reason its config cannot be managed at
	// all - empty when it can. Shown rather than hidden: it is a thing an
	// operator can fix, and finding out at delivery time is too late.
	Unmanageable string `json:"unmanageable,omitempty"`
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
	// unmanageable is the daemon's own reason its config cannot be
	// managed, empty when it can.
	unmanageable string
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

	// The daemon appends "unmanageable <why>" when its config cannot be
	// copied into a managed directory - an include naming a path rather
	// than a filename, most likely. Carrying it here means the operator
	// finds out when they look at the fleet, not when a delivery fails.
	why := ""
	if len(fields) >= 6 && fields[4] == "unmanageable" {
		why = strings.Join(fields[5:], " ")
	}

	d.conf.mu.Lock()
	d.conf.generation = gen
	d.conf.hash = fields[2]
	d.conf.files = files
	d.conf.asked = time.Now()
	d.conf.lastErr = ""
	d.conf.unmanageable = why
	d.conf.mu.Unlock()
}

// forgetHosts drops the object cache for a daemon whose config we just
// changed. The count check in the CONF merge would catch it a cycle later
// anyway, but we know right now that what we hold is out of date, and
// there is no reason to show an operator a host that no longer exists
// while they are looking at the delivery that removed it.
func (d *daemon) forgetHosts() {
	d.mu.Lock()
	d.hostCache = nil
	d.confSeq = 0
	d.fullResyncAt = time.Time{}
	d.mu.Unlock()
}

func (c *confState) setErr(msg string) {
	c.mu.Lock()
	c.lastErr = msg
	c.hash = ""
	c.mu.Unlock()
}

func (c *confState) snapshot() (gen uint64, hash string, files int, lastErr, lastReply, unmanageable string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation, c.hash, c.files, c.lastErr, c.lastReply, c.unmanageable
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

// flatName mirrors the daemon's rule: a config file is named, not
// located. Anything with a separator in it would have to become a path on
// the far side, and the far side does not accept paths.
func flatName(n string) bool {
	if n == "" || len(n) >= 128 {
		return false
	}
	if strings.ContainsRune(n, '/') || n == "." || n == ".." {
		return false
	}
	return true
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
			name, derr := base64.StdEncoding.DecodeString(f[1])
			if derr != nil {
				return nil, 0, "", fmt.Errorf("undecodable name in %s: %w", trimmed, derr)
			}
			declare, _ = strconv.Atoi(f[2])
			cur = &settings.GenFile{Name: string(name)}
			b64.Reset()
		case trimmed == "ENDFILE":
			if cur == nil {
				return nil, 0, "", fmt.Errorf("ENDFILE with no FILE")
			}
			content, derr := base64.StdEncoding.DecodeString(b64.String())
			if derr != nil {
				return nil, 0, "", fmt.Errorf("undecodable content for %s: %w", cur.Name, derr)
			}
			if len(content) != declare {
				return nil, 0, "", fmt.Errorf("%s declared %d bytes but carried %d",
					cur.Name, declare, len(content))
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
			base64.StdEncoding.EncodeToString([]byte(f.Name)), len(f.Content))
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

// revertConfig tells a box to stop being managed and go back to its seed
// config - the file an operator wrote, which the daemon has never touched.
//
// This is the way out, and it has to exist. Without it, adopting a box
// once would make its /etc config inert forever with no route back that
// does not involve somebody working out what the state directory is for.
func revertConfig(conn net.Conn, reader *bufio.Reader) (uint64, []string, error) {
	if _, err := conn.Write([]byte("CONFIG-REVERT\n")); err != nil {
		return 0, nil, err
	}
	code, complaints, err := readUntilCode(reader)
	if err != nil {
		return 0, complaints, err
	}
	if !strings.HasPrefix(code, "333") {
		return 0, complaints, fmt.Errorf("%s", code)
	}
	fields := strings.Fields(code)
	if len(fields) < 2 {
		return 0, complaints, fmt.Errorf("malformed revert reply: %s", code)
	}
	gen, _ := strconv.ParseUint(fields[1], 10, 64)
	return gen, complaints, nil
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

		gen, hash, files, confErr, lastReply, unmanageable := d.conf.snapshot()
		row := SiteConfigStatus{
			Site:              site,
			Description:       desc,
			RunningGeneration: gen,
			RunningHash:       hash,
			RunningFiles:      files,
			Reachable:         lastErr == "",
			LastError:         firstNonEmpty(lastErr, confErr),
			LastDelivery:      lastReply,
			Unmanageable:      unmanageable,
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

// withDaemonConn runs fn on the connection to a site.
//
// A daemon has one connection - the one it dialled in on - so the poller
// is locked out for the duration. That is correct: a delivery is not
// something to interleave with a status fetch on the same socket.
//
// No authentication step. The daemon verified our certificate before
// sending a byte and we verified its per-box token before answering, so
// the link is already proven both ways and asking it to AUTH would prove
// less.
func (s *Service) withDaemonConn(site string, fn func(net.Conn, *bufio.Reader) error) error {
	d := s.daemonFor(site)
	if d == nil {
		return fmt.Errorf("no site called %q is in the fleet", site)
	}

	d.mu.Lock()
	conn, reader := d.conn, d.reader
	d.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("site %q is not connected", site)
	}

	d.confMu.Lock()
	defer d.confMu.Unlock()
	conn.SetDeadline(time.Now().Add(120 * time.Second))
	defer conn.SetDeadline(time.Time{})
	return fn(conn, reader)
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
	names := make([]string, len(files))
	contents := make([][]byte, len(files))
	for i, f := range files {
		names[i], contents[i] = f.Name, f.Content
	}
	if mine := config.HashFileSet(names, contents); mine != hash {
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
		if err == nil {
			d.forgetHosts()
		}
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
		d.forgetHosts()
		d.conf.mu.Lock()
		d.conf.generation = res.RunningGeneration
		d.conf.hash = res.RunningHash
		d.conf.lastReply = fmt.Sprintf("rolled back to generation %d", res.RunningGeneration)
		d.conf.mu.Unlock()
	}
	return res, nil
}

// RevertSite tells a box to stop being managed.
//
// The desired state goes with it: a box that has been reverted is running
// its own config again, and leaving a desired generation recorded would
// only offer to overwrite it on the next poll.
func (s *Service) RevertSite(site string) (*DeliveryResult, error) {
	res := &DeliveryResult{Site: site}

	err := s.withDaemonConn(site, func(conn net.Conn, r *bufio.Reader) error {
		gen, complaints, e := revertConfig(conn, r)
		res.Complaints = complaints
		if e != nil {
			return e
		}
		res.Accepted = true
		res.RunningGeneration = gen
		return nil
	})
	if err != nil {
		return res, err
	}

	if store := s.Generations(); store != nil {
		store.Unadopt(site)
	}
	if d := s.daemonFor(site); d != nil {
		d.forgetHosts()
		d.conf.mu.Lock()
		d.conf.generation = 0
		d.conf.hash = ""
		d.conf.lastReply = "reverted to its own config"
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
	if !ValidSiteName(site) {
		return 0, "", fmt.Errorf(
			"%q is not a usable site name - letters, digits, - and _ only", site)
	}
	if len(files) == 0 {
		return 0, "", fmt.Errorf("a generation with no files would blank the box")
	}

	// Adoption first, and this is the gate that enforces it rather than
	// DeliverSite's.
	//
	// PutGeneration marks a site adopted as a side effect of storing a
	// generation, so staging into a site that was never adopted - or was
	// reverted, which zeroes the same fields - used to adopt it by
	// implication and hand DeliverSite everything it checks for. An edit
	// is a change to what a box runs, so it has to start from what the
	// box is running: without that, "changed" has no meaning and the
	// comparison below has nothing to compare against.
	desired, ok := store.GetDesired(site)
	if !ok || !desired.Adopted || desired.Generation == 0 {
		return 0, "", fmt.Errorf("%s has not been adopted; adopt it first so there is a "+
			"known starting point to edit from", site)
	}

	// Where the box reports is not editable from here. See uplink.go: the
	// daemon can be moved, but moving it also needs a certificate this
	// side cannot deliver, so a half-done move costs the box. Compared
	// against what this process already holds, which is what the operator
	// was looking at when they made the edit.
	//
	// Unconditional now. It used to be skipped whenever there was no
	// desired generation to compare against, which is exactly the state
	// an unadopted or reverted site is in - so the one path that could
	// move a box to another aggregator was the one the guard did not
	// watch.
	was, held := store.GetGenerationFiles(site, desired.Generation)
	if !held {
		return 0, "", fmt.Errorf(
			"generation %d of %s is not held here, so an edit cannot be checked against it",
			desired.Generation, site)
	}
	if err := checkUplinkUnchanged(was, files); err != nil {
		return 0, "", err
	}

	names := make([]string, len(files))
	contents := make([][]byte, len(files))
	for i, f := range files {
		// A name, never a path. The daemon decides which directory these
		// land in; this end only says what they are called, and anything
		// that looks like a path is a mistake worth catching here rather
		// than being refused three hops away.
		if !flatName(f.Name) {
			return 0, "", fmt.Errorf(
				"%q is not a plain filename - a generation names files, not paths", f.Name)
		}
		for j := 0; j < i; j++ {
			if files[j].Name == f.Name {
				return 0, "", fmt.Errorf("%q appears twice in one generation", f.Name)
			}
		}
		names[i], contents[i] = f.Name, f.Content
	}
	hash := config.HashFileSet(names, contents)

	gen, err := store.PutGeneration(site, files, hash, by, note)
	return gen, hash, err
}
