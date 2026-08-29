package api

import (
	"encoding/xml"
	"io"
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

// objectDetailFields is every ObjectStatus tag the detail page may see.
// Status, timing, counters, thresholds and queue state: what the page
// actually renders, and nothing that could carry a secret.
var objectDetailFields = map[string]bool{
	// Identity and configuration shape.
	"ObjectName":      true,
	"Object":          true,
	"HostName":        true,
	"ObjectType":      true,
	"ObjectPort":      true,
	"ObjectGroup":     true,
	"ObjectNotes":     true,
	"ObjectContact":   true,
	"ObjectUniqueID":  true,
	"ObjectDependent": true,

	// Current state.
	"ObjectStatus":         true,
	"ObjectMessage":        true,
	"ObjectAcked":          true,
	"ObjectAckedBy":        true,
	"ObjectAckNote":        true,
	"ObjectLastcheckState": true,
	"ObjectTraceEnabled":   true,
	"ObjectPaused":         true,
	"ObjectContacted":      true,
	"ObjectContactedAt":    true,
	"ObjectPageMessage":    true,

	// Counters and timings.
	"ObjectUpCt":         true,
	"ObjectDownCt":       true,
	"ObjectTotalChecked": true,
	"ObjectTotalDown":    true,
	"ObjectMaxDown":      true,
	"ObjectLastChecked":  true,
	"ObjectLastChange":   true,
	"ObjectTimeFailed":   true,
	"ChangeSeq":          true,

	// Queue / scheduler state.
	"ObjectQueued":         true,
	"ObjectQueueInterval":  true,
	"ObjectNextQueueTime":  true,
	"CheckQueuedAt":        true,
	"CheckStarted":         true,
	"CheckLastServiced":    true,
	"CheckLastWakeupTime":  true,
	"CheckWakeupCount":     true,
	"CheckFileDescriptor":  true,

	// Ping / RTT tuning and results.
	"ObjectSendPings":           true,
	"ObjectMinPings":            true,
	"ObjectRTTThreshold":        true,
	"ObjectJitterThreshold":     true,
	"ObjectPacketLossThreshold": true,
	"ObjectRTT":                 true,
	"ObjectJitter":              true,
	"ObjectPacketLoss":          true,

	// SNMP shape, but never the community.
	"ObjectSNMPOID":  true,
	"ObjectSNMPType": true,
}

// objectDetail parses an ObjectStatus document and returns only the
// allow-listed tags. Numbers come back as numbers so the page can format
// them without re-sniffing types in JavaScript.
func objectDetail(doc string) map[string]interface{} {
	out := map[string]interface{}{}
	dec := xml.NewDecoder(strings.NewReader(doc))
	var current string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A malformed tail still leaves what parsed cleanly; the
			// caller decides whether that is enough to render.
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			current = t.Name.Local
		case xml.CharData:
			if current == "" || !objectDetailFields[current] {
				continue
			}
			text := strings.TrimSpace(string(t))
			if text == "" {
				continue
			}
			if n, err := strconv.ParseFloat(text, 64); err == nil {
				out[current] = n
			} else {
				out[current] = text
			}
		case xml.EndElement:
			current = ""
		}
	}
	return out
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

	fields := objectDetail(doc)
	if len(fields) == 0 {
		// Say what happened without quoting the document: the raw
		// response is protocol debugging, and it is exactly the thing
		// this endpoint exists to stop handing out.
		r.sendError(w, http.StatusBadGateway,
			"object "+key+" returned a status document this server could not read")
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
