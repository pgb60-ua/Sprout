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
		dbRaw, errDB := os.ReadFile(r.dbPath)
		var files []remotecommon.BackupFile
		if errDB == nil {
			filepath.WalkDir(r.filesRoot, func(path string, info fs.DirEntry, err error) error {
				if err == nil && !info.IsDir() {
					if relPath, errRel := filepath.Rel(r.filesRoot, path); errRel == nil {
						if raw, errRead := os.ReadFile(path); errRead == nil { files = append(files, remotecommon.BackupFile{Path: relPath, Data: raw}) }
					}
				}
				return nil
			})
		}
		if errDB == nil {
			if raw, jsonErr := json.Marshal(remotecommon.BackupPayload{Timestamp: time.Now().UTC(), Source: "sprout", DBData: dbRaw, Files: files}); jsonErr == nil {
				if req, reqErr := http.NewRequest("POST", r.endpoint, bytes.NewReader(raw)); reqErr == nil {
					req.Header.Set("Content-Type", "application/json")
					if resp, callErr := r.client.Do(req); callErr == nil && resp.StatusCode < 400 {
						if resp != nil { resp.Body.Close() }
						return
					} else if callErr != nil { errDB = callErr } else { errDB = fmt.Errorf("codigo erroneo %s", resp.Status); resp.Body.Close() }
				}
			}
		}
		if r.local != nil && i == attempts { r.local.Printf("no se pudo enviar backup remoto tras %d intentos: %v", attempts, errDB) }
		select { case <-r.closed: return; case <-time.After(delay): }
	}
}
