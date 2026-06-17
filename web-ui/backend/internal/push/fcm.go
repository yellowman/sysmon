package push

import (
	"bytes"
	"context"
	"encoding/json"
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
	Sound string `json:"sound,omitempty"`
}

// fcmData carries the optional structured payload tagged onto each
// notification for use inside the app (host that flapped, new status,
// check type). All values must be strings in the v1 API.
type fcmData struct {
	Hostname string
	Status   string
	Type     string
}

func (d fcmData) toMap() map[string]string {
	if d.Hostname == "" && d.Status == "" && d.Type == "" {
		return nil
	}
	m := make(map[string]string, 3)
	if d.Hostname != "" {
		m["hostname"] = d.Hostname
	}
	if d.Status != "" {
		m["status"] = d.Status
	}
	if d.Type != "" {
		m["type"] = d.Type
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

// Send delivers a single notification to one device token.
func (c *FCMClient) Send(deviceToken string, title, body string, data fcmData) error {
	if deviceToken == "" {
		return fmt.Errorf("FCM Send: empty device token")
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
				Priority: "HIGH",
				Notification: &fcmV1AndroidNotification{
					Sound: "default",
				},
			},
		},
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal FCM v1 payload: %w", err)
	}

	tok, err := c.tokenSource.Token()
	if err != nil {
		return fmt.Errorf("mint FCM OAuth token: %w", err)
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
		// On 404 with errorCode UNREGISTERED the device token is dead;
		// the caller logs the failure and the next poll will keep the
		// subscription around. Pruning dead tokens is a separate job.
		return fmt.Errorf("FCM v1 error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
