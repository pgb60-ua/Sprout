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
	"sprout/pkg/server"
	"sprout/pkg/store"
	"sprout/pkg/utils"
)

type service struct {
	log     *log.Logger
	db      store.Store
	baseDir string
}

func Run() error {
	cfg, addr, baseDir := netcfg.Load(), os.Getenv("SPROUT_REMOTE_SERVICE_ADDR"), os.Getenv("SPROUT_REMOTE_SERVICE_DATA_DIR")
	if addr == "" { addr = ":8081" }
	if baseDir == "" { baseDir = "data/remote" }

	err := os.MkdirAll(baseDir, 0755)
	if err != nil {
		return err
	}
	db, err := store.NewStore("bbolt", filepath.Join(baseDir, "remote.db"))
	if err != nil {
		return err
	}
	s := &service{
		log:     log.New(os.Stdout, "[remote] ", log.LstdFlags),
		db:      db,
		baseDir: baseDir,
	}
	defer s.db.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/logs", s.withAuth(s.handleLogs))
	mux.HandleFunc("/backups", s.withAuth(s.handleBackups))

	s.log.Printf("servicio remoto escuchando en %s", addr)
	return (&http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}).ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
}

func (s *service) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		expected := "Bearer " + remotecommon.GetSharedSecret()
		if authHeader != expected {
			http.Error(w, "No autorizado", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func randomSuffix() string { t, _ := utils.NewRandomToken(8); return t }

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
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	payload, err := json.Marshal(event)
	if err != nil {
		http.Error(w, "Error empaquetando evento", http.StatusInternalServerError)
		return
	}
	key := []byte(fmt.Sprintf("%s-%s", event.Timestamp.UTC().Format(time.RFC3339Nano), randomSuffix()))
	
	encPayload, errEnc := server.EncryptUserdata(remotecommon.GetDEK(), payload)
	if errEnc == nil {
		payload = encPayload
	}

	err = s.db.Put("logs", key, payload)
	if err != nil {
		http.Error(w, "No se pudo persistir log", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *service) handleLogsList(w http.ResponseWriter, r *http.Request) {
	limit := 50
	limitStr := r.URL.Query().Get("limit")
	if limitStr != "" {
		v, err := strconv.Atoi(limitStr)
		if err == nil && v >= 0 {
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
		raw, err := s.db.Get("logs", []byte(k))
		if err == nil {
			if decRaw, errDec := server.DecryptUserdata(remotecommon.GetDEK(), raw); errDec == nil {
				raw = decRaw
			}
			var ev remotecommon.LogEvent
			errUnm := json.Unmarshal(raw, &ev)
			if errUnm == nil {
				events = append(events, ev)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(events)
	if err != nil {
		s.log.Printf("error enviando listado de logs: %v", err)
	}
}

func (s *service) handleBackups(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 20<<20)
	defer r.Body.Close()
	var req remotecommon.BackupPayload
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}
	if req.Timestamp.IsZero() {
		req.Timestamp = time.Now().UTC()
	}
	backupID := fmt.Sprintf("%s-%s", req.Timestamp.UTC().Format("20060102T150405.000000000Z"), randomSuffix())
	backupDir := filepath.Join(s.baseDir, "backups", backupID)
	err = os.MkdirAll(backupDir, 0700)
	if err != nil {
		http.Error(w, "No se pudo crear directorio de backup", http.StatusInternalServerError)
		return
	}
	encDB, errEnc := server.EncryptUserdata(remotecommon.GetDEK(), req.DBData)
	if errEnc == nil {
		req.DBData = encDB
	}
	err = os.WriteFile(filepath.Join(backupDir, "server.db"), req.DBData, 0600)
	if err != nil {
		http.Error(w, "No se pudo guardar DB", http.StatusInternalServerError)
		return
	}
	for _, f := range req.Files {
		cleanPath, cleanErr := sanitizeRelativePath(f.Path)
		if cleanErr != nil {
			http.Error(w, "Path inválido en backup", http.StatusBadRequest)
			return
		}
		target := filepath.Join(backupDir, "files", cleanPath)
		errMkdir := os.MkdirAll(filepath.Dir(target), 0700)
		if errMkdir != nil {
			http.Error(w, "No se pudo crear directorio del fichero", http.StatusInternalServerError)
			return
		}
		encFile, errEnc := server.EncryptUserdata(remotecommon.GetDEK(), f.Data)
		if errEnc == nil {
			f.Data = encFile
		}
		errWrite := os.WriteFile(target, f.Data, 0600)
		if errWrite != nil {
			http.Error(w, "No se pudo guardar fichero de backup", http.StatusInternalServerError)
			return
		}
	}
	meta, marshalErr := json.Marshal(map[string]any{
		"id":          backupID,
		"timestamp":   req.Timestamp.UTC(),
		"source":      req.Source,
		"db_bytes":    len(req.DBData),
		"files_count": len(req.Files),
	})
	if marshalErr != nil {
		s.log.Printf("error serializando metadata: %v", marshalErr)
	}
	err = s.db.Put("backups_meta", []byte(backupID), meta)
	if err != nil {
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
