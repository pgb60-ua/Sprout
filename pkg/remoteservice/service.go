package remoteservice

import (
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

	"sprout/pkg/store"
	"sprout/pkg/utils"
)

const (
	defaultAddrEnv       = "SPROUT_REMOTE_SERVICE_ADDR"
	defaultDataDirEnv    = "SPROUT_REMOTE_SERVICE_DATA_DIR"
	defaultTokenEnv      = "SPROUT_REMOTE_SERVICE_TOKEN"
	defaultListenAddress = ":8081"
	defaultDataDir       = "data/remote"
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

type service struct {
	log     *log.Logger
	db      store.Store
	baseDir string
	token   string
}

// Run inicia el servicio remoto combinado para logs y backups.
func Run() error {
	addr := os.Getenv(defaultAddrEnv)
	if addr == "" {
		addr = defaultListenAddress
	}

	baseDir := os.Getenv(defaultDataDirEnv)
	if baseDir == "" {
		baseDir = defaultDataDir
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return fmt.Errorf("error creando directorio remoto: %w", err)
	}

	remoteDBPath := filepath.Join(baseDir, "remote.db")
	db, err := store.NewStore("bbolt", remoteDBPath)
	if err != nil {
		return fmt.Errorf("error abriendo base remota: %w", err)
	}

	s := &service{
		log:     log.New(os.Stdout, "[remote] ", log.LstdFlags),
		db:      db,
		baseDir: baseDir,
		token:   os.Getenv(defaultTokenEnv),
	}
	defer s.db.Close()

	mux := http.NewServeMux()
	mux.Handle("/logs", http.HandlerFunc(s.handleLogs))
	mux.Handle("/backups", http.HandlerFunc(s.handleBackups))

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	s.log.Printf("servicio remoto escuchando en %s", addr)
	return httpSrv.ListenAndServe()
}

func (s *service) isAuthorized(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	return r.Header.Get("X-Sprout-Token") == s.token
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
	if !s.isAuthorized(r) {
		http.Error(w, "No autorizado", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var event remoteLogEvent
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&event); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	payload, err := json.Marshal(event)
	if err != nil {
		http.Error(w, "No se pudo serializar evento", http.StatusInternalServerError)
		return
	}

	key := []byte(fmt.Sprintf("%s-%s", event.Timestamp.UTC().Format(time.RFC3339Nano), randomSuffix()))
	if err := s.db.Put("logs", key, payload); err != nil {
		http.Error(w, "No se pudo persistir log", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (s *service) handleLogsList(w http.ResponseWriter, r *http.Request) {
	if !s.isAuthorized(r) {
		http.Error(w, "No autorizado", http.StatusUnauthorized)
		return
	}

	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		value, err := strconv.Atoi(q)
		if err != nil || value < 0 {
			http.Error(w, "limit invalido", http.StatusBadRequest)
			return
		}
		limit = value
	}

	keys, err := s.db.ListKeys("logs")
	if err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]remoteLogEvent{})
			return
		}
		http.Error(w, "No se pudieron listar logs", http.StatusInternalServerError)
		return
	}

	keyStrings := make([]string, 0, len(keys))
	for _, k := range keys {
		keyStrings = append(keyStrings, string(k))
	}
	sort.Strings(keyStrings)

	if limit > 0 && limit < len(keyStrings) {
		keyStrings = keyStrings[len(keyStrings)-limit:]
	}

	events := make([]remoteLogEvent, 0, len(keyStrings))
	for _, k := range keyStrings {
		raw, err := s.db.Get("logs", []byte(k))
		if err != nil {
			continue
		}
		var event remoteLogEvent
		if err := json.Unmarshal(raw, &event); err != nil {
			continue
		}
		events = append(events, event)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

func (s *service) handleBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}
	if !s.isAuthorized(r) {
		http.Error(w, "No autorizado", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 20<<20)
	defer r.Body.Close()

	var req backupPayload
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now().UTC()
	}

	backupID := fmt.Sprintf("%s-%s", req.Timestamp.UTC().Format("20060102T150405.000000000Z"), randomSuffix())
	backupDir := filepath.Join(s.baseDir, "backups", backupID)
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		http.Error(w, "No se pudo crear directorio de backup", http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(filepath.Join(backupDir, "server.db"), req.DBData, 0600); err != nil {
		http.Error(w, "No se pudo guardar DB", http.StatusInternalServerError)
		return
	}

	filesBaseDir := filepath.Join(backupDir, "files")
	for _, f := range req.Files {
		cleanPath, err := sanitizeRelativePath(f.Path)
		if err != nil {
			http.Error(w, "Path inválido en backup", http.StatusBadRequest)
			return
		}
		target := filepath.Join(filesBaseDir, cleanPath)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			http.Error(w, "No se pudo crear estructura de backup", http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(target, f.Data, 0600); err != nil {
			http.Error(w, "No se pudo guardar fichero de backup", http.StatusInternalServerError)
			return
		}
	}

	metadata := map[string]any{
		"id":         backupID,
		"timestamp":  req.Timestamp.UTC(),
		"source":     req.Source,
		"db_bytes":   len(req.DBData),
		"files_count": len(req.Files),
	}
	metaDataRaw, err := json.Marshal(metadata)
	if err != nil {
		http.Error(w, "No se pudo serializar metadata", http.StatusInternalServerError)
		return
	}
	if err := s.db.Put("backups_meta", []byte(backupID), metaDataRaw); err != nil {
		http.Error(w, "No se pudo persistir metadata", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func sanitizeRelativePath(p string) (string, error) {
	clean := filepath.Clean(p)
	if clean == "." || clean == string(filepath.Separator) {
		return "", errors.New("path vacío")
	}
	if strings.Contains(clean, "..") || filepath.IsAbs(clean) {
		return "", errors.New("path no permitido")
	}
	return clean, nil
}

func randomSuffix() string {
	token, err := utils.NewRandomToken(8)
	if err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return token
}
