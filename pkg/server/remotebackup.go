package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
	"sprout/pkg/remotecommon"
)

type remoteBackupSender struct {
	endpoint, dbPath, filesRoot string
	client                      *http.Client
	local                       *log.Logger
	closed                      chan struct{}
	closeOnce                   sync.Once
}

func newRemoteBackupSenderFromEnv(endpoint, caFile, dbPath, filesRoot string, local *log.Logger) *remoteBackupSender {
	if endpoint == "" { return nil }
	client, err := remotecommon.NewHTTPClient(endpoint, caFile, 10*time.Second)
	if err != nil {
		if local != nil { local.Printf("no se pudo inicializar cliente TLS remoto para backups: %v", err) }
		return nil
	}
	r := &remoteBackupSender{
		endpoint: endpoint, 
		client: client, 
		local: local,
		closed: make(chan struct{}),
		dbPath: dbPath,
		filesRoot: filesRoot,
	}
	go func() {
		r.send(5, 300*time.Millisecond)
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C: r.send(3, 300*time.Millisecond)
			case <-r.closed: return
			}
		}
	}()
	return r
}

func (r *remoteBackupSender) Close() {
	if r != nil {
		r.closeOnce.Do(func() {
			close(r.closed)}) 
	} 
}

func (r *remoteBackupSender) send(attempts int, delay time.Duration) {
	if r == nil { return }
	for i := 1; i <= attempts; i++ {
		err := r.attemptSend()
		if err == nil {
			return
		}
		if r.local != nil && i == attempts {
			r.local.Printf("no se pudo enviar backup remoto tras %d intentos: %v", attempts, err)
		}
		select {
		case <-r.closed: 
			return
		case <-time.After(delay):
		}
	}
}

func (r *remoteBackupSender) attemptSend() error {
	dbRaw, err := os.ReadFile(r.dbPath)
	if err != nil {
		return err
	}

	var files []remotecommon.BackupFile
	_ = filepath.WalkDir(r.filesRoot, func(path string, info fs.DirEntry, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(r.filesRoot, path)
		if err != nil {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		files = append(files, remotecommon.BackupFile{Path: relPath, Data: raw})
		return nil
	})

	payload := remotecommon.BackupPayload{
		Timestamp: time.Now().UTC(),
		Source:    "sprout",
		DBData:    dbRaw,
		Files:     files,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", r.endpoint, bytes.NewReader(raw))
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
