package api

import (
	"encoding/json"
	"strings"
	"testing"

	"sysmon-web/internal/auth"
	"sysmon-web/internal/monitoring"
)

// The daemon's SHOWOBJ document as it looks for an object with every
// credential-bearing field set. Before this fix the host detail page
// fetched exactly this and handed it to the browser, so a read-only user
// could read all of it out of devtools.
const secretMarker = "SECRET-DO-NOT-LEAK"

func showobjWithSecrets() string {
	return `<ObjectStatus>` +
		`<Object>awbreyrouter</Object>` +
		`<HostName>10.20.4.1</HostName>` +
		`<ObjectType>snmp</ObjectType>` +
		`<ObjectPort>161</ObjectPort>` +
		`<ObjectGroup>tower-awbrey</ObjectGroup>` +
		`<ObjectNotes>Awbrey tower router</ObjectNotes>` +
		`<ObjectUpCt>412</ObjectUpCt>` +
		`<ObjectDownCt>3</ObjectDownCt>` +
		`<ObjectQueueInterval>60</ObjectQueueInterval>` +
		`<ObjectTraceEnabled>0</ObjectTraceEnabled>` +
		`<ObjectRTTThreshold>250</ObjectRTTThreshold>` +
		// Everything below must never reach a browser.
		`<ObjectSNMPCommunity>` + secretMarker + `</ObjectSNMPCommunity>` +
		`<ObjectAuthUsername>` + secretMarker + `</ObjectAuthUsername>` +
		`<ObjectAuthPassword>` + secretMarker + `</ObjectAuthPassword>` +
		`<ObjectRadiusSecret>` + secretMarker + `</ObjectRadiusSecret>` +
		`<ObjectHeader>` + secretMarker + `</ObjectHeader>` +
		`<ObjectHeaderValue>` + secretMarker + `</ObjectHeaderValue>` +
		`<ObjectURL>https://user:` + secretMarker + `@example.com/health</ObjectURL>` +
		`<ObjectURLText>` + secretMarker + `</ObjectURLText>` +
		`<ObjectExecCmd>/usr/bin/page --token ` + secretMarker + `</ObjectExecCmd>` +
		`</ObjectStatus>`
}

func TestObjectDetailOmitsEveryCredential(t *testing.T) {
	fields := objectDetail(showobjWithSecrets())

	blob, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), secretMarker) {
		t.Fatalf("host detail leaked a credential: %s", blob)
	}

	// And it still carries what the page renders, or the fix broke the
	// page instead of securing it.
	for _, want := range []string{
		"HostName", "ObjectType", "ObjectPort", "ObjectGroup", "ObjectNotes",
		"ObjectUpCt", "ObjectDownCt", "ObjectQueueInterval", "ObjectTraceEnabled",
		"ObjectRTTThreshold",
	} {
		if _, ok := fields[want]; !ok {
			t.Errorf("detail dropped %s, which the page renders", want)
		}
	}
	// Numbers arrive as numbers.
	if v, ok := fields["ObjectUpCt"].(float64); !ok || v != 412 {
		t.Errorf("ObjectUpCt = %v, want numeric 412", fields["ObjectUpCt"])
	}
}

// An unknown tag is not carried just because it looks harmless: the
// allow-list is the whole mechanism, so a field added to the daemon's
// XML later stays out until somebody adds it here deliberately.
func TestObjectDetailIsAnAllowListNotABlockList(t *testing.T) {
	doc := `<ObjectStatus><ObjectSomethingInventedTomorrow>` + secretMarker +
		`</ObjectSomethingInventedTomorrow><HostName>gw</HostName></ObjectStatus>`
	fields := objectDetail(doc)
	if _, ok := fields["ObjectSomethingInventedTomorrow"]; ok {
		t.Fatal("an unknown tag was passed through; the list is not doing its job")
	}
	if fields["HostName"] != "gw" {
		t.Fatalf("known tag lost: %+v", fields)
	}
}

// The XML parse-error path is the other way the daemon's raw response
// used to reach a browser: on malformed status XML the handler returned
// raw_xml, samples and all_responses to any authenticated caller, and
// those fields hold exactly the credential-bearing document above.
//
// This drives the policy function with a real XMLParseError rather than
// poking the endpoint on a router with no daemon behind it - that
// request never reaches this branch, so such a test passes whatever the
// branch does, which is the opposite of a regression barrier.
func TestParseErrorDetailsAreAdminOnly(t *testing.T) {
	e := &monitoring.XMLParseError{
		Message:    "XML parse failure on awbreyrouter",
		ObjectName: "awbreyrouter",
		RawXML: "<ObjectStatus><ObjectAuthPassword>" + secretMarker +
			"</ObjectAuthPassword><ObjectSNMPCommunity>" + secretMarker +
			"</ObjectSNMPCommunity></ObjectStatu",
		AllSamples: []map[string]string{
			{"sample": "<ObjectRadiusSecret>" + secretMarker + "</ObjectRadiusSecret>"},
		},
		AllResponses: []monitoring.ResponseCapture{
			{Command: "SHOWOBJ awbreyrouter", Parsed: false,
				Response: "<ObjectExecCmd>/usr/bin/page --token " + secretMarker + "</ObjectExecCmd>"},
		},
	}

	// A plain user: which object is broken, and nothing else.
	msg, details := xmlParseErrorResponse(e, auth.RoleUser)
	blob, err := json.Marshal(map[string]interface{}{"message": msg, "details": details})
	if err != nil {
		t.Fatal(err)
	}
	body := string(blob)
	if strings.Contains(body, secretMarker) {
		t.Fatalf("a plain user's error carries a credential: %s", body)
	}
	for _, field := range []string{"raw_xml", "samples", "all_responses"} {
		if strings.Contains(body, field) {
			t.Errorf("a plain user's error carries %s: %s", field, body)
		}
	}
	if !strings.Contains(msg, "awbreyrouter") {
		t.Errorf("the user is not told which object is broken: %q", msg)
	}

	// An empty role is not an admin either - the header is absent on
	// any path that has not been through the session middleware.
	if _, d := xmlParseErrorResponse(e, ""); d["raw_xml"] != nil {
		t.Error("an unknown role got the protocol dump")
	}

	// An admin keeps the diagnostics: they can read the config anyway,
	// and this is the payload that makes a parse failure debuggable.
	adminMsg, adminDetails := xmlParseErrorResponse(e, auth.RoleAdmin)
	if adminMsg != e.Message {
		t.Errorf("admin message = %q, want the parser's own %q", adminMsg, e.Message)
	}
	for _, field := range []string{"raw_xml", "samples", "all_responses"} {
		if adminDetails[field] == nil {
			t.Errorf("admin lost %s, so a parse failure is no longer debuggable", field)
		}
	}
}
