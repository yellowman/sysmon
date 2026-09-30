package api

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	"sysmon-web/internal/auth"
	"sysmon-web/internal/monitoring"
)

// The host detail page used to fetch /api/xml/object/<key> and hand the
// daemon's whole SHOWOBJ response to the browser. That response carries
// the credentials an object's checks run with - SNMP community, check
// username and password, RADIUS shared secret, HTTP header value, URL
// and the command a failure executes. The page rendered none of them,
// which is not the same as not sending them: the browser had them, and
// anyone who could open devtools could read them. On an install with
// read-only NOC accounts that is a credential handout, because the
// endpoint sat on the ordinary authenticated side of the router.
//
// So detail gets its own endpoint with a positive allow-list of tags, on
// the same principle as the topology endpoint: fields are named to be
// included rather than named to be stripped. A credential tag added to
// send_object_xml() later cannot appear here by having been forgotten in
// a blocklist - it simply is not on the list.

// How a field's text is carried to the page.
type detailKind int

const (
	// kindAuto: numeric-looking text becomes a JSON number, so the page
	// can compare and format it without re-sniffing types.
	kindAuto detailKind = iota
	// kindText: keep the daemon's text exactly as sent. The queue
	// timestamps are "seconds.microseconds" (%ld.%06ld), which is a
	// formatted string, not a quantity: float64 holds about 15.95
	// significant digits and a current epoch with microseconds needs 16,
	// so a tenth of all values lose their trailing digit on the way
	// through. The status parser has always kept these as strings for
	// the same reason.
	kindText
)

// objectDetailFields is every ObjectStatus tag the detail page may see.
// Status, timing, counters, thresholds and queue state: what the page
// actually renders, and nothing that could carry a secret.
//
// The names must match the daemon's XML_* defines exactly - a tag named
// wrongly here is simply dropped, silently, since this is an allow-list.
// TestObjectDetailFieldsExistInTheDaemon cross-checks every one of them
// against src/config.h.
var objectDetailFields = map[string]detailKind{
	// Identity and configuration shape.
	"Object":         kindAuto,
	"HostName":       kindAuto,
	"ObjectType":     kindAuto,
	"ObjectPort":     kindAuto,
	"ObjectGroup":    kindAuto,
	"ObjectNotes":    kindAuto,
	"ObjectContact":  kindAuto,
	"ObjectUniqueID": kindAuto,

	// Current state.
	"ObjectStatus":         kindAuto,
	"ObjectMessage":        kindAuto,
	"ObjectAcked":          kindAuto,
	"ObjectLastcheckState": kindAuto,
	"ObjectTraceEnabled":   kindAuto,
	"ObjectContacted":      kindAuto,
	"ObjectContactedAt":    kindAuto,
	"ObjectPageMessage":    kindAuto,

	// Counters and timings.
	"ObjectUpCt":         kindAuto,
	"ObjectDownCt":       kindAuto,
	"ObjectTotalChecked": kindAuto,
	"ObjectTotalDown":    kindAuto,
	"ObjectMaxDown":      kindAuto,
	"ObjectLastTimeUp":   kindAuto,
	"ObjectLastChecked":  kindAuto,
	"ObjectChangeSeq":    kindAuto,

	// Queue / scheduler state.
	"ObjectQueued":        kindAuto,
	"ObjectQueueInterval": kindAuto,
	"ObjectNextQueueTime": kindAuto,
	"CheckQueuedAt":       kindText,
	"CheckStarted":        kindAuto,
	"CheckLastServiced":   kindText,
	"CheckLastWakeupTime": kindAuto,
	"CheckWakeupCount":    kindAuto,
	"CheckFileDescriptor": kindAuto,

	// Ping / RTT tuning and results.
	"ObjectSendPings":           kindAuto,
	"ObjectMinPings":            kindAuto,
	"ObjectRTTThreshold":        kindAuto,
	"ObjectJitterThreshold":     kindAuto,
	"ObjectPacketLossThreshold": kindAuto,
	"ObjectAvgRTT":              kindAuto,
	"ObjectJitter":              kindAuto,
	"ObjectPacketLoss":          kindAuto,

	// SNMP shape, but never the community.
	"ObjectSNMPoid":  kindAuto,
	"ObjectSNMPType": kindAuto,
}

// objectDetail parses one ObjectStatus document and returns only the
// allow-listed tags. Numeric fields come back as numbers so the page can
// compare and format them without re-sniffing types in JavaScript.
//
// It refuses anything that is not exactly one complete, well-formed
// ObjectStatus document, instead of returning whatever parsed before the
// problem. A prefix is not a partial answer, it is a wrong one: every
// field after the break is missing, and the page cannot tell a field the
// daemon never sent from a field that was cut off, so it renders a
// plausible host detail that quietly omits the half it lost. The daemon
// formats each line with snprintf into a fixed buffer, which truncates
// an oversized value silently and takes its closing tag with it - that
// is the realistic way a document arrives whole but broken.
//
// The decoder alone does not enforce this. It reports syntax errors
// (a truncated tail, a mismatched tag, a bad entity) but accepts an
// empty input, a different root element, two documents back to back and
// stray text around the root without complaint. Those are structural
// questions, so they are checked here.
//
// The error never quotes the document. A decoder message can carry a
// fragment of it, and the privileged SHOWOBJ this server makes returns
// the object's credentials - callers must not pass err to a browser.
func objectDetail(doc string) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	dec := xml.NewDecoder(strings.NewReader(doc))

	var (
		current             string
		depth               int
		sawRoot, closedRoot bool
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("malformed status document: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				if closedRoot {
					return nil, errors.New("a second element follows the status document")
				}
				if t.Name.Local != "ObjectStatus" {
					return nil, fmt.Errorf("expected an ObjectStatus document, got <%s>", t.Name.Local)
				}
				sawRoot = true
			}
			depth++
			current = t.Name.Local
		case xml.EndElement:
			depth--
			if depth == 0 {
				closedRoot = true
			}
			current = ""
		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if depth == 0 {
				// Outside the root only whitespace belongs. Anything else
				// means the stream was not the document we asked for.
				if text != "" {
					return nil, errors.New("text outside the status document")
				}
				continue
			}
			kind, ok := objectDetailFields[current]
			if !ok || text == "" {
				continue
			}
			if n, err := strconv.ParseFloat(text, 64); kind == kindAuto && err == nil {
				out[current] = n
			} else {
				out[current] = text
			}
		}
	}
	if !sawRoot {
		return nil, errors.New("no ObjectStatus document in the response")
	}
	if !closedRoot {
		// The decoder reports this itself as unexpected EOF; checked
		// again so the rule does not rest on that behaviour.
		return nil, errors.New("status document ended before </ObjectStatus>")
	}
	return out, nil
}

// handleObjectDetail serves the host detail page:
// GET /api/monitoring/object-detail/<object key>.
//
// Available to any authenticated user, because it carries no secrets.
// The raw-XML endpoint it replaces is admin-only now.
func (r *Router) handleObjectDetail(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		r.sendError(w, http.StatusMethodNotAllowed, "Only GET allowed")
		return
	}
	key := strings.TrimSpace(strings.TrimPrefix(req.URL.Path, "/api/monitoring/object-detail/"))
	if key == "" {
		r.sendError(w, http.StatusBadRequest, "Object name required")
		return
	}

	doc, err := r.monitoring.GetObjectXML(key)
	if err != nil {
		if strings.Contains(err.Error(), "object not found") {
			r.sendError(w, http.StatusNotFound, err.Error())
			return
		}
		r.sendError(w, http.StatusServiceUnavailable, "Failed to get object detail: "+err.Error())
		return
	}

	r.writeObjectDetail(w, key, doc)
}

// writeObjectDetail turns a fetched status document into the response.
//
// Split out of the handler so the refusal path can be tested against a
// real malformed document; through the handler it cannot be, because
// fetching one needs a daemon.
func (r *Router) writeObjectDetail(w http.ResponseWriter, key, doc string) {
	fields, err := objectDetail(doc)
	if err != nil {
		// Logged here, never sent: a decoder message can quote a
		// fragment of the privileged document - Go's quotes a bad
		// entity's name verbatim. The page gets which object and that
		// it failed, which is the part it can act on; an admin wanting
		// the document itself has /api/xml/object/.
		log.Printf("object-detail %s: %v", key, err)
		r.sendError(w, http.StatusBadGateway,
			"object "+key+" returned a status document this server could not read - it was incomplete or malformed")
		return
	}
	r.sendJSON(w, fields)
}

// xmlParseErrorResponse decides what a malformed-status-XML failure may
// say to whom.
//
// The debug payload is the daemon's raw SHOWOBJ/CONF response, which
// carries the object's SNMP community, check password, RADIUS secret,
// header value and command line. That is protocol debugging: it goes to
// an admin, who can read the config anyway, and to nobody else. Everyone
// else is told which object is broken, which is the part they can act
// on.
//
// Split out of the handler so the policy can be tested against a real
// XMLParseError. Tested through the handler it could not be: a router
// with no daemon behind it never reaches this branch, so the test would
// pass while the branch handed out raw XML to the world.
func xmlParseErrorResponse(e *monitoring.XMLParseError, role string) (string, map[string]interface{}) {
	if role == auth.RoleAdmin {
		return e.Message, map[string]interface{}{
			"object_name":   e.ObjectName,
			"raw_xml":       e.RawXML,
			"samples":       e.AllSamples,
			"all_responses": e.AllResponses,
		}
	}
	msg := "a monitored object returned malformed status XML"
	if e.ObjectName != "" {
		msg = "object " + e.ObjectName + " returned malformed status XML"
	}
	return msg, map[string]interface{}{"object_name": e.ObjectName}
}
