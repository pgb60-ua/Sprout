package remoteservice

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"sprout/pkg/netcfg"
	"sprout/pkg/remotecommon"
	"sprout/pkg/store"
	"sprout/pkg/utils"
)

const (
	defaultListenAddress = ":8081"
	defaultDataDir       = "data/remote"
)

type service struct {
	log     *log.Logger
	db      store.Store
	baseDir string
}

func Run() error {
	cfg := netcfg.Load()
	addr := getEnv("SPROUT_REMOTE_SERVICE_ADDR", defaultListenAddress)
	baseDir := getEnv("SPROUT_REMOTE_SERVICE_DATA_DIR", defaultDataDir)

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return err
	}

	db, err := store.NewStore("bbolt", filepath.Join(baseDir, "remote.db"))
	if err != nil {
		return err
	}

	s := &service{log: log.New(os.Stdout, "[remote] ", log.LstdFlags), db: db, baseDir: baseDir}
	defer s.db.Close()

	mux := http.NewServeMux()
	mux.Handle("/logs", http.HandlerFunc(s.handleLogs))
	mux.Handle("/backups", http.HandlerFunc(s.handleBackups))

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	s.log.Printf("servicio remoto escuchando en %s", addr)
	return httpSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func (s *service) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.handleLogsList(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var event remotecommon.LogEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	payload, _ := json.Marshal(event)
	key := []byte(fmt.Sprintf("%s-%s", event.Timestamp.UTC().Format(time.RFC3339Nano), randomSuffix()))
	if err := s.db.Put("logs", key, payload); err != nil {
		http.Error(w, "No se pudo persistir log", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *service) handleLogsList(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v >= 0 {
			limit = v
		}
	}

	keys, err := s.db.ListKeys("logs")
	if err != nil && !errors.Is(err, store.ErrNamespaceNotFound) {
		http.Error(w, "No se pudieron listar logs", http.StatusInternalServerError)
		return
	}

	keyStrings := make([]string, len(keys))
	for i, k := range keys {
		keyStrings[i] = string(k)
	}
	sort.Strings(keyStrings)
	if limit > 0 && limit < len(keyStrings) {
		keyStrings = keyStrings[len(keyStrings)-limit:]
	}

	var events []remotecommon.LogEvent
	for _, k := range keyStrings {
		if raw, err := s.db.Get("logs", []byte(k)); err == nil {
			var ev remotecommon.LogEvent
			if json.Unmarshal(raw, &ev) == nil {
				events = append(events, ev)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

func (s *service) handleBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 20<<20)
	defer r.Body.Close()

	var req remotecommon.BackupPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now().UTC()
	}

	backupID := fmt.Sprintf("%s-%s", req.Timestamp.UTC().Format("20060102T150405.000000000Z"), randomSuffix())
	backupDir := filepath.Join(s.baseDir, "backups", backupID)
	os.MkdirAll(backupDir, 0700)

	if err := os.WriteFile(filepath.Join(backupDir, "server.db"), req.DBData, 0600); err != nil {
		http.Error(w, "No se pudo guardar DB", http.StatusInternalServerError)
		return
	}
	for _, f := range req.Files {
		if cleanPath, err := sanitizeRelativePath(f.Path); err == nil {
			target := filepath.Join(backupDir, "files", cleanPath)
			os.MkdirAll(filepath.Dir(target), 0700)
			if err := os.WriteFile(target, f.Data, 0600); err != nil {
				http.Error(w, "No se pudo guardar fichero de backup", http.StatusInternalServerError)
				return
			}
		} else {
			http.Error(w, "Path inválido en backup", http.StatusBadRequest)
			return
		}
	}

	meta, _ := json.Marshal(map[string]any{
		"id": backupID, "timestamp": req.Timestamp.UTC(), "source": req.Source,
		"db_bytes": len(req.DBData), "files_count": len(req.Files),
	})
	if err := s.db.Put("backups_meta", []byte(backupID), meta); err != nil {
		http.Error(w, "No se pudo persistir metadata", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func sanitizeRelativePath(p string) (string, error) {
	clean := filepath.Clean(p)
	if clean == "." || clean == string(filepath.Separator) || filepath.IsAbs(clean) || strings.Contains(clean, "..") {
		return "", errors.New("path no permitido o inválido")
	}
	return clean, nil
}

func randomSuffix() string {
	tok, err := utils.NewRandomToken(8)
	if err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return tok
}
