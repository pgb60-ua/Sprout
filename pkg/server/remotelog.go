package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
	"sprout/pkg/remotecommon"
)

type remoteLogger struct {
	endpoint string
	client   *http.Client
	events   chan remotecommon.LogEvent
	closed   chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
	local    *log.Logger
}

func newRemoteLoggerFromEnv(endpoint, caFile string, local *log.Logger) *remoteLogger {
	if endpoint == "" { return nil }
	client, err := remotecommon.NewHTTPClient(endpoint, caFile, 3*time.Second)
	if err != nil {
		if local != nil { local.Printf("no se pudo inicializar cliente TLS remoto: %v", err) }
		return nil
	}
	rl := &remoteLogger{endpoint: endpoint,
		client: client,
		events: make(chan remotecommon.LogEvent, 100),
		closed: make(chan struct{}),
		local: local,
	}

	rl.wg.Add(1)
	go func() {
		defer rl.wg.Done()
		for {
			select {
			case event := <-rl.events: rl.send(event)
			case <-rl.closed: return
			}
		}
	}()
	return rl
}

func (r *remoteLogger) Enqueue(event remotecommon.LogEvent) {
	if r == nil { return }
	select { case <-r.closed: case r.events <- event: default: if r.local != nil { r.local.Printf("cola llena; descarta action=%s", event.Action) } }
}

func (r *remoteLogger) CloseWithTimeout(timeout time.Duration) {
	if r == nil { return }
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r.once.Do(func() {
		for { select { case event := <-r.events: _ = r.send(event); default: close(r.closed); return } }
	})
	waitDone := make(chan struct{})
	go func() { r.wg.Wait(); close(waitDone) }()
	select { case <-waitDone: case <-ctx.Done(): }
}

func (r *remoteLogger) send(event remotecommon.LogEvent) error {
	event.Source = "sprout"
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", r.endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("codigo erroneo %s", resp.Status)
	}
	return nil
}