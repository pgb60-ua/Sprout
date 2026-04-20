package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"context"
)

type remoteLogEvent struct {
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

type remoteLogger struct {
	endpoint string
	client   *http.Client
	events   chan remoteLogEvent
	closed   chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
	local    *log.Logger
}

func newRemoteLoggerFromEnv(endpoint, caFile string, local *log.Logger) *remoteLogger {
	if endpoint == "" {
		return nil
	}
	return newRemoteLogger(endpoint, caFile, local)
}

func newRemoteLogger(endpoint, caFile string, local *log.Logger) *remoteLogger {
	client, err := newRemoteHTTPClient(endpoint, caFile, 3*time.Second)
	if err != nil {
		if local != nil {
			local.Printf("no se pudo inicializar cliente TLS remoto: %v", err)
		}
		return nil
	}

	rl := &remoteLogger{
		endpoint: endpoint,
		client:   client,
		events:   make(chan remoteLogEvent, 100),
		closed:   make(chan struct{}),
		local:    local,
	}
	rl.wg.Add(1)
	go rl.run()
	return rl
}

func (r *remoteLogger) Enqueue(event remoteLogEvent) {
	if r == nil {
		return
	}
	select {
	case <-r.closed:
		return
	case r.events <- event:
	default:
		if r.local != nil {
			r.local.Printf("cola de logging remoto llena; se descarta evento action=%s user=%s", event.Action, event.Username)
		}
	}
}

func (r *remoteLogger) CloseWithTimeout(timeout time.Duration) {
	if r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r.once.Do(func() {
		for {
			select {
			case event := <-r.events:
				_ = r.send(event)
			default:
				close(r.closed)
				return
			}
		}
	})
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-ctx.Done():
		if r.local != nil {
			r.local.Printf("remoteLogger: cierre forzado tras timeout, puede haber eventos no enviados")
		}
		return
	}
}

func (r *remoteLogger) run() {
	defer r.wg.Done()
	for {
		select {
		case event := <-r.events:
			if err := r.send(event); err != nil && r.local != nil {
				r.local.Printf("no se pudo enviar evento remoto: %v", err)
			}
		case <-r.closed:
			return
		}
	}
}

func (r *remoteLogger) send(event remoteLogEvent) error {
	event.Source = "sprout"
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("error serializando evento remoto: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, r.endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("error construyendo request remoto: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("error enviando evento remoto: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("endpoint remoto devolvió status %s", resp.Status)
	}
	return nil
}

func newRemoteHTTPClient(endpoint, caFile string, timeout time.Duration) (*http.Client, error) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(endpoint)), "https://") {
		return &http.Client{Timeout: timeout}, nil
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer la CA en %q: %w", caFile, err)
	}

	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("el fichero %q no contiene certificados PEM validos", caFile)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		},
	}

	return &http.Client{Timeout: timeout, Transport: transport}, nil
}