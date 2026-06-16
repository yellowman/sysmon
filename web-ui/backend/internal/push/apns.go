package push

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
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
	Badge *int      `json:"badge,omitempty"`
}

type apnsAlert struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Body     string `json:"body"`
}

// NewAPNsClient builds an APNs client from a PEM cert + key (raw bytes,
// e.g. uploaded through the admin UI and stored in bbolt).
func NewAPNsClient(certPEM, keyPEM []byte, bundleID string, production bool) (*APNsClient, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
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

// APNsCertMeta validates an APNs cert+key pair and returns display-safe
// metadata. Error text is written to be shown to an admin.
func APNsCertMeta(certPEM, keyPEM []byte) (subject string, notAfter time.Time, err error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("cert and key don't form a valid pair: %w", err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		if len(pair.Certificate) == 0 {
			return "", time.Time{}, fmt.Errorf("certificate is empty")
		}
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return "", time.Time{}, fmt.Errorf("parse certificate: %w", err)
		}
	}
	return leaf.Subject.CommonName, leaf.NotAfter, nil
}

func (c *APNsClient) Send(deviceToken string, title, subtitle, body string, badge *int) error {
	payload := apnsPayload{
		Aps: apnsAps{
			Alert: apnsAlert{
				Title:    title,
				Subtitle: subtitle,
				Body:     body,
			},
			Sound: "default",
			Badge: badge,
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
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("APNs error %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
