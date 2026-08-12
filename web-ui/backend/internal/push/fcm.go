package push

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// FCMScope is the OAuth scope required for the FCM HTTP v1 API.
const fcmScope = "https://www.googleapis.com/auth/firebase.messaging"

// Notification channel IDs pinned server-side, so the OS→channel mapping
// is explicit rather than relying on the app's manifest default. MUST
// match the channels the Android app creates at startup
// (SysmonApplication) and the ids in
// android/app/src/main/res/values/strings.xml. Critical alerts ride the
// high-importance channel (sound, heads-up); warnings and recoveries
// ride the low-importance one (silent, shade-only).
const (
	androidChannelID     = "sysmon_alerts"
	androidWarnChannelID = "sysmon_warnings"
)

// collapseKey64 truncates a collapse key to APNs' 64-byte limit.
func collapseKey64(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// FCMClient talks to the FCM HTTP v1 endpoint
// (https://fcm.googleapis.com/v1/projects/{project}/messages:send) using
// short-lived OAuth access tokens minted from a Google service-account
// JSON file. The token source caches and refreshes the token
// automatically, so callers can just call Send().
//
// The deprecated legacy /fcm/send + "Authorization: key=..." flow used
// before this migration was shut down by Google in June 2024 and is
// gone for good.
type FCMClient struct {
	httpClient  *http.Client
	tokenSource oauth2.TokenSource
	projectID   string
	endpoint    string
}

// FCM v1 send request body.
// Docs: https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages
type fcmV1Request struct {
	Message fcmV1Message `json:"message"`
}

type fcmV1Message struct {
	Token        string             `json:"token"`
	Notification *fcmV1Notification `json:"notification,omitempty"`
	Data         map[string]string  `json:"data,omitempty"`
	Android      *fcmV1Android      `json:"android,omitempty"`
	APNS         *fcmV1APNs         `json:"apns,omitempty"`
}

type fcmV1Notification struct {
	Title string `json:"title,omitempty"`
	Body  string `json:"body,omitempty"`
}

type fcmV1Android struct {
	Priority     string                    `json:"priority,omitempty"` // "HIGH" or "NORMAL"
	Notification *fcmV1AndroidNotification `json:"notification,omitempty"`
}

type fcmV1AndroidNotification struct {
	Sound     string `json:"sound,omitempty"`
	ChannelID string `json:"channel_id,omitempty"`
	// Same tag -> newer notification replaces the older one, so a WARN
	// vanishes when the CRIT (or the recovery) for that host arrives.
	Tag string `json:"tag,omitempty"`
}

// APNs overlay for iOS tokens registered through Firebase (FCM relays to
// APNs using the auth key uploaded in the Firebase console). Ignored for
// Android registration tokens, so it's always safe to include.
type fcmV1APNs struct {
	Headers map[string]string `json:"headers,omitempty"`
	Payload *fcmV1APNsPayload `json:"payload,omitempty"`
}

type fcmV1APNsPayload struct {
	APS fcmV1APS `json:"aps"`
}

type fcmV1APS struct {
	Alert fcmV1APSAlert `json:"alert"`
	Sound string        `json:"sound,omitempty"`
	Badge *int          `json:"badge,omitempty"`
	// See apnsAps.InterruptionLevel.
	InterruptionLevel string `json:"interruption-level,omitempty"`
}

type fcmV1APSAlert struct {
	Title    string `json:"title,omitempty"`
	Subtitle string `json:"subtitle,omitempty"`
	Body     string `json:"body,omitempty"`
}

// fcmData carries the optional structured payload tagged onto each
// notification for use inside the app (host that flapped, new status,
// check type, the measured figures behind the change). All values must
// be strings in the v1 API.
type fcmData struct {
	Hostname string
	Object   string // object name - the app's notification-replacement key
	Status   string
	Type     string
	Details  string // "rtt avg 143.2ms (limit 80ms)", "reading 52 (max 45)", …
}

func (d fcmData) toMap() map[string]string {
	if d.Hostname == "" && d.Object == "" && d.Status == "" && d.Type == "" && d.Details == "" {
		return nil
	}
	m := make(map[string]string, 5)
	if d.Hostname != "" {
		m["hostname"] = d.Hostname
	}
	if d.Object != "" {
		m["object_name"] = d.Object
	}
	if d.Status != "" {
		m["status"] = d.Status
	}
	if d.Type != "" {
		m["type"] = d.Type
	}
	if d.Details != "" {
		m["details"] = d.Details
	}
	return m
}

// serviceAccountFields are the parts of a Google service-account JSON we
// care about for validation and display. The full credential is handed
// to the oauth2 library; this is just for our own checks/metadata.
type serviceAccountFields struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

// FCMCredentialMeta validates a service-account JSON and returns
// display-safe metadata (never the private key). Used both to vet an
// upload and to render the "currently configured" panel. The error
// messages are written to be shown to an admin in the UI.
func FCMCredentialMeta(credentialsJSON []byte) (projectID, clientEmail, keyIDLast4 string, err error) {
	var sa serviceAccountFields
	if e := json.Unmarshal(credentialsJSON, &sa); e != nil {
		return "", "", "", fmt.Errorf("not valid JSON: %w", e)
	}
	if sa.Type != "service_account" {
		// Most common mistake: uploading google-services.json (the
		// client config bundled into the Android app) instead of the
		// service-account key.
		return "", "", "", fmt.Errorf("this is not a service-account key (type=%q). Use Firebase Console → Project Settings → Service accounts → \"Generate new private key\", not the google-services.json app file", sa.Type)
	}
	if sa.ProjectID == "" || sa.ClientEmail == "" || sa.TokenURI == "" {
		return "", "", "", fmt.Errorf("service-account JSON is missing required fields (project_id/client_email/token_uri)")
	}
	if !strings.Contains(sa.PrivateKey, "BEGIN PRIVATE KEY") {
		return "", "", "", fmt.Errorf("service-account JSON has no usable private_key")
	}
	// Final authority: let the oauth2 library actually accept it.
	if _, e := google.CredentialsFromJSON(context.Background(), credentialsJSON, fcmScope); e != nil {
		return "", "", "", fmt.Errorf("Google rejected the credentials: %w", e)
	}
	last4 := sa.PrivateKeyID
	if len(last4) > 4 {
		last4 = last4[len(last4)-4:]
	}
	return sa.ProjectID, sa.ClientEmail, last4, nil
}

// KeyRejectedError means Google itself refused the service-account key
// (revoked, deleted, or fundamentally unusable) - as opposed to a
// transient network failure reaching Google, which is NOT evidence the
// key is bad.
type KeyRejectedError struct{ Detail string }

func (e *KeyRejectedError) Error() string { return e.Detail }

// classifyTokenError turns an OAuth token-mint failure into a
// KeyRejectedError when Google answered with an auth error, or returns
// the error wrapped as-is for network trouble.
func classifyTokenError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		body := strings.TrimSpace(string(re.Body))
		if len(body) > 300 {
			body = body[:300] + "…"
		}
		code := 0
		if re.Response != nil {
			code = re.Response.StatusCode
		}
		return &KeyRejectedError{Detail: fmt.Sprintf(
			"Google rejected the service-account key (HTTP %d): %s - the key has likely been revoked or deleted. Generate a new one in Firebase Console → Project Settings → Service accounts",
			code, body)}
	}
	return fmt.Errorf("could not reach Google to verify the key: %w", err)
}

// FCMCredentialLiveCheck proves Google currently accepts the key by
// minting a real OAuth access token. FCMCredentialMeta is offline-only -
// a revoked key still parses fine - so this is the only way to catch a
// dead key before alert delivery silently stops. Returns nil on success,
// *KeyRejectedError when Google definitively refused the key, and other
// errors for network trouble.
func FCMCredentialLiveCheck(ctx context.Context, credentialsJSON []byte) error {
	creds, err := google.CredentialsFromJSON(ctx, credentialsJSON, fcmScope)
	if err != nil {
		return &KeyRejectedError{Detail: fmt.Sprintf("credentials unusable: %v", err)}
	}
	if _, err := creds.TokenSource.Token(); err != nil {
		return classifyTokenError(err)
	}
	return nil
}

// FCMSendError classifies a v1 send failure so callers can react -
// prune dead tokens, flag a project mismatch, or recheck the key.
type FCMSendError struct {
	StatusCode int
	Reason     string // FCM errorCode: UNREGISTERED, SENDER_ID_MISMATCH, …
	Body       string
}

func (e *FCMSendError) Error() string {
	switch e.Reason {
	case "UNREGISTERED":
		return fmt.Sprintf("FCM: device token is no longer valid (app uninstalled or token rotated) [HTTP %d]", e.StatusCode)
	case "SENDER_ID_MISMATCH":
		return fmt.Sprintf("FCM: device token belongs to a DIFFERENT Firebase project than this service-account key - the app was built with a google-services.json from another project [HTTP %d]", e.StatusCode)
	default:
		return fmt.Sprintf("FCM v1 error %d (%s): %s", e.StatusCode, e.Reason, e.Body)
	}
}

// parseFCMErrorReason extracts the machine-readable errorCode from an
// FCM v1 error response body, falling back to the google.rpc status.
func parseFCMErrorReason(body []byte) string {
	var parsed struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				Type      string `json:"@type"`
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return ""
	}
	for _, d := range parsed.Error.Details {
		if d.ErrorCode != "" {
			return d.ErrorCode
		}
	}
	return parsed.Error.Status
}

// NewFCMClient builds an FCM client from a Google service-account
// credentials JSON (the raw bytes, e.g. as uploaded through the admin UI
// and stored in bbolt). The token source it builds refreshes access
// tokens transparently.
func NewFCMClient(credentialsJSON []byte) (*FCMClient, error) {
	if len(credentialsJSON) == 0 {
		return nil, fmt.Errorf("FCM credentials are empty")
	}
	creds, err := google.CredentialsFromJSON(context.Background(), credentialsJSON, fcmScope)
	if err != nil {
		return nil, fmt.Errorf("parse FCM credentials: %w", err)
	}
	if creds.ProjectID == "" {
		return nil, fmt.Errorf("FCM credentials have no project_id; upload a service-account key, not an OAuth client")
	}
	return &FCMClient{
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		tokenSource: creds.TokenSource,
		projectID:   creds.ProjectID,
		endpoint:    fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", creds.ProjectID),
	}, nil
}

// Send delivers a single notification to one device token. Both the
// android and apns config blocks are always included: FCM applies
// whichever matches the token's platform and ignores the other, so one
// payload shape serves Android registration tokens and Firebase-relayed
// iOS tokens alike. subtitle and badge only render on iOS.
//
// critical=true (host down) means sound + heads-up/time-sensitive;
// false (warnings, recoveries) means silent, low-importance delivery.
// collapseKey makes newer notifications for the same host replace older
// ones on both platforms.
func (c *FCMClient) Send(deviceToken string, title, subtitle, body string, badge *int, data fcmData, critical bool, collapseKey string) error {
	if deviceToken == "" {
		return fmt.Errorf("FCM Send: empty device token")
	}

	androidPriority := "NORMAL"
	androidNotif := &fcmV1AndroidNotification{
		ChannelID: androidWarnChannelID,
		Tag:       collapseKey,
	}
	aps := fcmV1APS{
		Alert: fcmV1APSAlert{
			Title:    title,
			Subtitle: subtitle,
			Body:     body,
		},
		Badge:             badge,
		InterruptionLevel: "passive",
	}
	apnsPriority := "5"
	if critical {
		// Canonical AndroidMessagePriority enum name. The v1 API also
		// accepts lowercase "high" (Google's own docs use it), and an
		// actually-invalid value would be a 400, never a silent
		// downgrade.
		androidPriority = "HIGH"
		androidNotif.Sound = "default"
		androidNotif.ChannelID = androidChannelID
		aps.Sound = "default"
		aps.InterruptionLevel = "time-sensitive"
		apnsPriority = "10"
	}
	apnsHeaders := map[string]string{
		"apns-priority":  apnsPriority,
		"apns-push-type": "alert",
	}
	if collapseKey != "" {
		apnsHeaders["apns-collapse-id"] = collapseKey64(collapseKey)
	}

	req := fcmV1Request{
		Message: fcmV1Message{
			Token: deviceToken,
			Notification: &fcmV1Notification{
				Title: title,
				Body:  body,
			},
			Data: data.toMap(),
			Android: &fcmV1Android{
				Priority:     androidPriority,
				Notification: androidNotif,
			},
			APNS: &fcmV1APNs{
				Headers: apnsHeaders,
				Payload: &fcmV1APNsPayload{APS: aps},
			},
		},
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal FCM v1 payload: %w", err)
	}

	tok, err := c.tokenSource.Token()
	if err != nil {
		// A definitive OAuth refusal here means the key died after being
		// stored (revoked/deleted). classifyTokenError surfaces that as
		// KeyRejectedError so the service can flip the key-health status.
		return classifyTokenError(err)
	}

	httpReq, err := http.NewRequest("POST", c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create FCM v1 request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	httpReq.Header.Set("Content-Type", "application/json; charset=UTF-8")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("FCM v1 request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		body := strings.TrimSpace(string(respBody))
		if len(body) > 300 {
			body = body[:300] + "…"
		}
		return &FCMSendError{
			StatusCode: resp.StatusCode,
			Reason:     parseFCMErrorReason(respBody),
			Body:       body,
		}
	}

	return nil
}
