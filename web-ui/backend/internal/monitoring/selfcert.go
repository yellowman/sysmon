package monitoring

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A certificate for the agent listener, generated once if the operator has
// not supplied one.
//
// The listener is on by default and TLS on it is not optional - it carries
// a bearer token and, later, whole configs - which would make "no
// certificate" mean "no fleet" out of the box. Requiring a CA before
// anything works is the kind of default that gets worked around rather
// than followed, usually by turning verification off somewhere.
//
// So: generate one, keep it, and print what a daemon needs to trust it.
// This is a real key pair with real verification at the other end, pinned
// by file rather than by a public CA. Each box gets the certificate as
// `config aggregator-ca`, and sysmond still verifies the name it dialled -
// self-signed is not the same as unverified.
//
// An operator with a proper CA passes -agent-cert/-agent-key and none of
// this runs.

const (
	selfCertName = "agent-cert.pem"
	selfKeyName  = "agent-key.pem"
	selfCertLife = 10 * 365 * 24 * time.Hour
)

// EnsureAgentCert returns paths to a certificate and key for the agent
// listener, generating a self-signed pair in dir on first use.
//
// hosts are the names and addresses a daemon might dial this process by.
// Getting them wrong is the one failure that shows up much later - as a
// hostname-verification error on a box someone is trying to onboard - so
// they go in the certificate rather than being left to chance.
func EnsureAgentCert(dir string, hosts []string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, selfCertName)
	keyPath = filepath.Join(dir, selfKeyName)

	if fileUsable(certPath) && fileUsable(keyPath) {
		return certPath, keyPath, nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "sysmon-web agent listener"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(selfCertLife),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	if len(tmpl.DNSNames) == 0 && len(tmpl.IPAddresses) == 0 {
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	// 0600: this is the thing that lets something impersonate the
	// aggregator to every box in the fleet.
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}

// The certificate this process is actually serving on the agent
// listener, remembered so the admin page can hand it out. A box needs it
// as aggregator-ca.pem, and telling somebody to go and find a file on the
// server is how they end up copying the wrong one.
var agentCertPath struct {
	mu   sync.Mutex
	path string
}

func SetAgentCertPath(p string) {
	agentCertPath.mu.Lock()
	agentCertPath.path = p
	agentCertPath.mu.Unlock()
}

func AgentCertPath() string {
	agentCertPath.mu.Lock()
	defer agentCertPath.mu.Unlock()
	return agentCertPath.path
}

// What a box should put in "config aggregator".
//
// The page, the API and the command line all print this line, and a box
// that gets it wrong fails in a way that looks like a network fault. So
// one function makes it and one variable holds the answer.
var agentDial struct {
	mu     sync.Mutex
	target string
}

func SetAgentDialTarget(t string) {
	agentDial.mu.Lock()
	agentDial.target = t
	agentDial.mu.Unlock()
}

func AgentDialTarget() string {
	agentDial.mu.Lock()
	defer agentDial.mu.Unlock()
	return agentDial.target
}

// DefaultAgentPort is the one place the agent listener's port number
// lives. The -agent-listen flag default and DialTarget's fallback both
// read it, so they cannot drift apart.
const DefaultAgentPort = "1347"

// DialTarget builds that line from the two flags that decide it.
//
// The name comes from -agent-names, because that is what the certificate
// was made for and the daemon verifies it. The port comes from
// -agent-listen, because a hardcoded 1347 hands somebody on another port
// a config that cannot connect.
func DialTarget(agentNames, agentListen string) string {
	port := DefaultAgentPort
	if _, p, err := net.SplitHostPort(agentListen); err == nil && p != "" {
		port = p
	}
	return net.JoinHostPort(firstName(agentNames), port)
}

// firstName is the name a box should dial. -agent-names is what the
// certificate was made for, so its first entry is the one most likely to
// work.
func firstName(agentNames string) string {
	for _, n := range strings.Split(agentNames, ",") {
		if n = strings.TrimSpace(n); n != "" {
			return n
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "sysmon-web.example.net"
}

// CertNames lists what a generated certificate is valid for, so the log
// can say it and an operator can tell at a glance whether the name their
// daemons dial is in there.
func CertNames(certPath string) (string, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", fmt.Errorf("%s is not PEM", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	names := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		return cert.Subject.CommonName, nil
	}
	return fmt.Sprintf("%v", names), nil
}

func fileUsable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Size() > 0
}
