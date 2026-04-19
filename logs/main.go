package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"go.etcd.io/bbolt"
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

func main() {
	dbPath := flag.String("db", "data/remote/remote.db", "ruta de la bbolt remota")
	endpoint := flag.String("endpoint", "http://localhost:8081/logs", "endpoint HTTP para leer logs en caliente")
	token := flag.String("token", os.Getenv("SPROUT_REMOTE_SERVICE_TOKEN"), "token para cabecera X-Sprout-Token")
	limit := flag.Int("limit", 50, "numero maximo de logs a mostrar (0 = todos)")
	asJSON := flag.Bool("json", false, "imprime cada log como JSON crudo")
	flag.Parse()

	resolvedPath, err := resolveDBPath(*dbPath)
	if err != nil {
		entries, fetchErr := readLogsHTTP(*endpoint, *token, *limit)
		if fetchErr != nil {
			log.Fatalf("%v. %v", err, fetchErr)
		}
		printEntries(entries, *limit, *asJSON)
		return
	}

	db, err := bbolt.Open(resolvedPath, 0600, &bbolt.Options{
		ReadOnly: true,
		Timeout:  1 * time.Second,
	})
	if err != nil {
		entries, fetchErr := readLogsHTTP(*endpoint, *token, *limit)
		if fetchErr != nil {
			log.Fatalf("no se pudo abrir la base de logs: %v. y tampoco se pudieron obtener por HTTP: %v", err, fetchErr)
		}
		printEntries(entries, *limit, *asJSON)
		return
	}
	defer db.Close()

	entries := make(map[string][]byte)
	err = db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("logs"))
		if bucket == nil {
			return nil
		}

		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			kCopy := make([]byte, len(k))
			copy(kCopy, k)
			vCopy := make([]byte, len(v))
			copy(vCopy, v)
			entries[string(kCopy)] = vCopy
		}
		return nil
	})
	if err != nil {
		log.Fatalf("no se pudieron leer logs: %v", err)
	}

	printEntries(entries, *limit, *asJSON)
}

func printEntries(entries map[string][]byte, limit int, asJSON bool) {
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		fmt.Println("No hay logs remotos guardados.")
		return
	}
	sort.Strings(keys)

	if limit > 0 && limit < len(keys) {
		keys = keys[len(keys)-limit:]
	}

	for _, k := range keys {
		raw := entries[k]

		if asJSON {
			fmt.Println(string(raw))
			continue
		}

		var ev remoteLogEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			fmt.Printf("[%s] <json invalido> %s\n", k, string(raw))
			continue
		}

		fmt.Printf("%s level=%s action=%s user=%s success=%t ip=%s path=%s msg=%s\n",
			ev.Timestamp.UTC().Format(time.RFC3339),
			ev.Level,
			ev.Action,
			emptyDash(ev.Username),
			ev.Success,
			emptyDash(ev.RemoteAddr),
			emptyDash(ev.Path),
			ev.Message,
		)
	}
}

func readLogsHTTP(endpoint, token string, limit int) (map[string][]byte, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("limit", fmt.Sprintf("%d", limit))
	req.URL.RawQuery = q.Encode()

	if token != "" {
		req.Header.Set("X-Sprout-Token", token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("endpoint HTTP devolvio status %s", resp.Status)
	}

	var events []remoteLogEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, err
	}

	entries := make(map[string][]byte, len(events))
	for i, ev := range events {
		raw, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%03d-%s", i, ev.Timestamp.UTC().Format(time.RFC3339Nano))
		entries[key] = raw
	}
	return entries, nil
}

func resolveDBPath(path string) (string, error) {
	candidates := []string{path}
	if !filepath.IsAbs(path) {
		candidates = append(candidates, filepath.Join("..", "..", path))
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("no se encontro la base remota en %v", candidates)
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
