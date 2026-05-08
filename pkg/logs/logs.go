package logs

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	"go.etcd.io/bbolt"
	"sprout/pkg/remotecommon"
)

func Run() {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	dbPath := fs.String("db", "data/remote/remote.db", "ruta de la bbolt remota")
	endpoint := fs.String("endpoint", "https://localhost:8081/logs", "endpoint HTTPS para leer logs en caliente")
	caFile := fs.String("ca", "data/certs/ca-cert.pem", "ruta del certificado CA para validar TLS")
	limit := fs.Int("limit", 50, "numero maximo de logs a mostrar (0 = todos)")
	asJSON := fs.Bool("json", false, "imprime cada log como JSON crudo")
	fs.Parse(nil)

	entries := make(map[string][]byte)

	if db, err := bbolt.Open(*dbPath, 0600, &bbolt.Options{ReadOnly: true, Timeout: time.Second}); err == nil {
		defer db.Close()
		_ = db.View(func(tx *bbolt.Tx) error {
			if b := tx.Bucket([]byte("logs")); b != nil {
				c := b.Cursor()
				for k, v := c.First(); k != nil; k, v = c.Next() {
					val := make([]byte, len(v))
					copy(val, v)
					entries[string(k)] = val
				}
			}
			return nil
		})
	} else if evs, e := fetchLogs(*endpoint, *caFile, *limit); e == nil {
		for i, ev := range evs {
			if raw, e2 := json.Marshal(ev); e2 == nil {
				entries[fmt.Sprintf("%03d-%s", i, ev.Timestamp.UTC().Format(time.RFC3339Nano))] = raw
			}
		}
	} else {
		log.Fatalf("no se pudo leer la base de logs remotos ni obtenerlos por HTTP: db_err(%v), http_err(%v)", err, e)
	}

	keys := make([]string, 0, len(entries))
	for k := range entries { keys = append(keys, k) }
	
	if len(keys) == 0 {
		fmt.Println("No hay logs remotos guardados.")
		return
	}
	sort.Strings(keys)

	if *limit > 0 && *limit < len(keys) { keys = keys[len(keys)-*limit:] }

	for _, k := range keys {
		if *asJSON {
			fmt.Println(string(entries[k]))
			continue
		}
		var ev remotecommon.LogEvent
		if json.Unmarshal(entries[k], &ev) == nil {
			fmt.Printf("%s level=%s action=%s user=%s success=%t ip=%s path=%s msg=%s\n",
				ev.Timestamp.UTC().Format(time.RFC3339), ev.Level, ev.Action, 
				valOr(ev.Username), ev.Success, valOr(ev.RemoteAddr), valOr(ev.Path), ev.Message)
		}
	}
}

func fetchLogs(endpoint, caFile string, limit int) ([]remotecommon.LogEvent, error) {
	client, err := remotecommon.NewHTTPClient(endpoint, caFile, 3*time.Second)
	if err != nil { return nil, fmt.Errorf("error inicializando cliente TLS: %w", err) }

	req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	q := req.URL.Query()
	q.Set("limit", fmt.Sprint(limit))
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil { return nil, fmt.Errorf("error al hacer petición HTTP: %w", err) }
	defer resp.Body.Close()

	if resp.StatusCode >= 400 { return nil, fmt.Errorf("el endpoint devolvio status %s", resp.Status) }
	
	var evs []remotecommon.LogEvent
	err = json.NewDecoder(resp.Body).Decode(&evs)
	return evs, err
}

func valOr(s string) string {
	if s == "" { return "-" }
	return s
}
