package remotecommon

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type LogEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Level      string    `json:"level"`
	Action     string    `json:"action"`
	Username   string    `json:"username,omitempty"`
	RemoteAddr string    `json:"remote_addr,omitempty"`
	Path       string    `json:"path,omitempty"`
	Success    bool      `json:"success"`
	Message    string    `json:"message"`
	Source     string    `json:"source"`
}

type BackupFile struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
}

type BackupPayload struct {
	Timestamp time.Time    `json:"timestamp"`
	Source    string       `json:"source"`
	DBData    []byte       `json:"db_data"`
	Files     []BackupFile `json:"files"`
}

func NewHTTPClient(endpoint, caFile string, timeout time.Duration) (*http.Client, error) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(endpoint)), "https://") {
		return &http.Client{Timeout: timeout}, nil
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer CA %q: %w", caFile, err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA invalida en %q", caFile)
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs},
		},
	}, nil
}
