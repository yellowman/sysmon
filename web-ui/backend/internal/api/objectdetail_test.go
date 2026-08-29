package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"sysmon-web/internal/auth"
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
// those fields hold exactly the credential-bearing document above. A
// plain user gets told which object is broken; the protocol dump is for
// an admin, who can read the config anyway.
func TestParseErrorDetailsAreAdminOnly(t *testing.T) {
	handler, authSvc, stop := testRouter(t)
	defer stop()

	userToken := sessionFor(t, authSvc, "viewer3", "pw-viewer", auth.RoleUser)

	req := httptest.NewRequest("GET", "/api/monitoring/status", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Whatever this router answers with no daemon behind it, the one
	// thing the body must never contain is a raw protocol dump.
	body := rec.Body.String()
	for _, field := range []string{"raw_xml", "all_responses", "samples"} {
		if strings.Contains(body, field) {
			t.Errorf("a plain user's error body carries %s: %s", field, body)
		}
	}
}
