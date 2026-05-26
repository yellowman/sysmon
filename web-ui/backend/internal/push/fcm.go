package push

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const fcmURL = "https://fcm.googleapis.com/fcm/send"

type FCMClient struct {
	httpClient *http.Client
	serverKey  string
}

type fcmMessage struct {
	To           string          `json:"to"`
	Priority     string          `json:"priority"`
	Notification fcmNotification `json:"notification"`
	Data         fcmData         `json:"data,omitempty"`
}

type fcmNotification struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	Sound string `json:"sound,omitempty"`
}

type fcmData struct {
	Hostname string `json:"hostname,omitempty"`
	Status   string `json:"status,omitempty"`
	Type     string `json:"type,omitempty"`
}

func NewFCMClient(serverKey string) *FCMClient {
	return &FCMClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		serverKey:  serverKey,
	}
}

func (c *FCMClient) Send(deviceToken string, title, body string, data fcmData) error {
	msg := fcmMessage{
		To:       deviceToken,
		Priority: "high",
		Notification: fcmNotification{
			Title: title,
			Body:  body,
			Sound: "default",
		},
		Data: data,
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal FCM message: %w", err)
	}

	req, err := http.NewRequest("POST", fcmURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("create FCM request: %w", err)
	}

	req.Header.Set("Authorization", "key="+c.serverKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("FCM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("FCM error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
