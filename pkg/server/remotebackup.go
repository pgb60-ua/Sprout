package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const defaultRemoteBackupInterval = 60 * time.Second

type backupFile struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
}

type backupPayload struct {
	Timestamp time.Time    `json:"timestamp"`
	Source    string       `json:"source"`
	DBData    []byte       `json:"db_data"`
	Files     []backupFile `json:"files"`
}

type remoteBackupSender struct {
	endpoint   string
	token      string
	client     *http.Client
	interval   time.Duration
	local      *log.Logger
	closed     chan struct{}
	closeOnce  sync.Once
	dbPath     string
	filesRoot  string
}

func newRemoteBackupSenderFromEnv(endpoint, token, dbPath, filesRoot string, local *log.Logger) *remoteBackupSender {
	if endpoint == "" {
		return nil
	}
	r := &remoteBackupSender{
		endpoint:  endpoint,
		token:     token,
		client:    &http.Client{Timeout: 10 * time.Second},
		interval:  defaultRemoteBackupInterval,
		local:     local,
		closed:    make(chan struct{}),
		dbPath:    dbPath,
		filesRoot: filesRoot,
	}
	go r.run()
	return r
}

func (r *remoteBackupSender) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		close(r.closed)
	})
}

func (r *remoteBackupSender) run() {
	r.sendSnapshotWithRetry(5, 300*time.Millisecond)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.sendSnapshotWithRetry(3, 300*time.Millisecond)
		case <-r.closed:
			return
		}
	}
}

func (r *remoteBackupSender) sendSnapshotWithRetry(attempts int, delay time.Duration) {
	if r == nil {
		return
	}
	if attempts < 1 {
		attempts = 1
	}

	for i := 1; i <= attempts; i++ {
		if err := r.sendSnapshot(); err == nil {
			return
		} else if r.local != nil && i == attempts {
			r.local.Printf("no se pudo enviar backup remoto tras %d intentos: %v", attempts, err)
		}

		select {
		case <-r.closed:
			return
		case <-time.After(delay):
		}
	}
}

func (r *remoteBackupSender) sendSnapshot() error {
	if r == nil {
		return nil
	}
	payload, err := r.buildPayload()
	if err != nil {
		return fmt.Errorf("no se pudo construir backup remoto: %w", err)
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("no se pudo serializar backup remoto: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, r.endpoint, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("no se pudo crear request backup remoto: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if r.token != "" {
		req.Header.Set("X-Sprout-Token", r.token)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("no se pudo enviar backup remoto: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("endpoint de backup remoto devolvió status %s", resp.Status)
	}

	return nil
}

func (r *remoteBackupSender) buildPayload() (backupPayload, error) {
	dbRaw, err := os.ReadFile(r.dbPath)
	if err != nil {
		return backupPayload{}, fmt.Errorf("error leyendo DB principal: %w", err)
	}

	files := make([]backupFile, 0)
	err = filepath.WalkDir(r.filesRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(r.filesRoot, path)
		if err != nil {
			return err
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, backupFile{
			Path: relPath,
			Data: raw,
		})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return backupPayload{}, fmt.Errorf("error leyendo ficheros de usuario: %w", err)
	}

	return backupPayload{
		Timestamp: time.Now().UTC(),
		Source:    "sprout",
		DBData:    dbRaw,
		Files:     files,
	}, nil
}
