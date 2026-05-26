package push

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	apnsSandboxURL    = "https://api.sandbox.push.apple.com"
	apnsProductionURL = "https://api.push.apple.com"
)

type APNsClient struct {
	httpClient *http.Client
	baseURL    string
	bundleID   string
}

type apnsPayload struct {
	Aps apnsAps `json:"aps"`
}

type apnsAps struct {
	Alert apnsAlert `json:"alert"`
	Sound string    `json:"sound"`
}

type apnsAlert struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Body     string `json:"body"`
}

func NewAPNsClient(certFile, keyFile, bundleID string, production bool) (*APNsClient, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load APNs cert/key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	baseURL := apnsSandboxURL
	if production {
		baseURL = apnsProductionURL
	}

	return &APNsClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
			Timeout: 10 * time.Second,
		},
		baseURL:  baseURL,
		bundleID: bundleID,
	}, nil
}

func (c *APNsClient) Send(deviceToken string, title, subtitle, body string) error {
	payload := apnsPayload{
		Aps: apnsAps{
			Alert: apnsAlert{
				Title:    title,
				Subtitle: subtitle,
				Body:     body,
			},
			Sound: "default",
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal APNs payload: %w", err)
	}

	url := fmt.Sprintf("%s/3/device/%s", c.baseURL, deviceToken)
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("create APNs request: %w", err)
	}

	req.Header.Set("apns-topic", c.bundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	req.Header.Set("apns-expiration", "0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("APNs request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("APNs error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
