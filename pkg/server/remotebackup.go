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

	"sprout/pkg/remotecommon"
)

const defaultRemoteBackupInterval = 60 * time.Second

type remoteBackupSender struct {
	endpoint   string
	client     *http.Client
	interval   time.Duration
	local      *log.Logger
	closed     chan struct{}
	closeOnce  sync.Once
	dbPath     string
	filesRoot  string
}

func newRemoteBackupSenderFromEnv(endpoint, caFile, dbPath, filesRoot string, local *log.Logger) *remoteBackupSender {
	if endpoint == "" {
		return nil
	}

	client, err := remotecommon.NewHTTPClient(endpoint, caFile, 10*time.Second)
	if err != nil {
		if local != nil {
			local.Printf("no se pudo inicializar cliente TLS remoto para backups: %v", err)
		}
		return nil
	}

	r := &remoteBackupSender{
		endpoint:  endpoint,
		client:    client,
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
	if r != nil {
		r.closeOnce.Do(func() { close(r.closed) })
	}
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
	for i := 1; i <= max(1, attempts); i++ {
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
		return err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("no se pudo serializar backup remoto: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, r.endpoint, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("no se pudo crear petición HTTP: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("no se pudo hacer request POST al endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("el servidor de logs devolvió codigo http erroneo (%s)", resp.Status)
	}
	return nil
}

func (r *remoteBackupSender) buildPayload() (remotecommon.BackupPayload, error) {
	dbRaw, err := os.ReadFile(r.dbPath)
	if err != nil {
		return remotecommon.BackupPayload{}, fmt.Errorf("error leyendo DB principal: %w", err)
	}

	var files []remotecommon.BackupFile
	err = filepath.WalkDir(r.filesRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		relPath, _ := filepath.Rel(r.filesRoot, path)
		if raw, err := os.ReadFile(path); err == nil {
			files = append(files, remotecommon.BackupFile{Path: relPath, Data: raw})
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return remotecommon.BackupPayload{}, fmt.Errorf("error construyendo lista de ficheros para backup: %w", err)
	}

	return remotecommon.BackupPayload{
		Timestamp: time.Now().UTC(),
		Source:    "sprout",
		DBData:    dbRaw,
		Files:     files,
	}, nil
}
