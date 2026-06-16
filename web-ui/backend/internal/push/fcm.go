package push

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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

// NewFCMClient loads a Google service-account credentials JSON file and
// returns an FCM client configured for that file's project. The token
// source it builds refreshes access tokens transparently.
//
// Pass the absolute path of the JSON downloaded from
// Firebase Console -> Project Settings -> Service Accounts ->
// "Generate new private key".
func NewFCMClient(credentialsFile string) (*FCMClient, error) {
	if credentialsFile == "" {
		return nil, fmt.Errorf("FCM credentials file path is empty")
	}
	data, err := os.ReadFile(credentialsFile)
	if err != nil {
		return nil, fmt.Errorf("read FCM credentials %q: %w", credentialsFile, err)
	}
	creds, err := google.CredentialsFromJSON(context.Background(), data, fcmScope)
	if err != nil {
		return nil, fmt.Errorf("parse FCM credentials %q: %w", credentialsFile, err)
	}
	if creds.ProjectID == "" {
		return nil, fmt.Errorf("FCM credentials %q has no project_id; download a service-account key, not an OAuth client", credentialsFile)
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
