package logs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"go.etcd.io/bbolt"
	"sprout/pkg/remotecommon"
)

func Run() {
	dbPath, endpoint, caFile := "data/remote/remote.db", "https://localhost:8081/logs", "data/certs/ca-cert.pem"
	entries := make(map[string][]byte)

	if db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{ReadOnly: true, Timeout: time.Second}); err == nil {
		defer db.Close()
		_ = db.View(func(tx *bbolt.Tx) error {
			if b := tx.Bucket([]byte("logs")); b != nil {
				c := b.Cursor()
				for k, v := c.First(); k != nil; k, v = c.Next() {
					entries[string(k)] = append([]byte(nil), v...)
				}
			}
			return nil
		})
	} else if cli, e := remotecommon.NewHTTPClient(endpoint, caFile, 3*time.Second); e == nil {
		if req, _ := http.NewRequest("GET", endpoint+"?limit=50", nil); req != nil {
			if resp, e2 := cli.Do(req); e2 == nil && resp.StatusCode < 400 {
				defer resp.Body.Close()
				var evs []remotecommon.LogEvent
				if json.NewDecoder(resp.Body).Decode(&evs) == nil {
					for i, ev := range evs {
						if raw, e3 := json.Marshal(ev); e3 == nil {
							entries[fmt.Sprintf("%03d-%s", i, ev.Timestamp.UTC().Format(time.RFC3339Nano))] = raw
						}
					}
				}
			}
		}
	} else {
		fmt.Printf("No se pudo leer la base de logs remotos ni obtenerlos por HTTP: %v\n", err)
		return
	}

	keys := make([]string, 0, len(entries))
	for k := range entries { keys = append(keys, k) }
	
	if len(keys) == 0 {
		fmt.Println("No hay logs remotos guardados.")
		return
	}
	sort.Strings(keys)

	if len(keys) > 50 { keys = keys[len(keys)-50:] }

	for _, k := range keys {
		var ev remotecommon.LogEvent
		if json.Unmarshal(entries[k], &ev) == nil {
			fmt.Printf("%s level=%s action=%s user=%s success=%t ip=%s path=%s msg=%s\n",
				ev.Timestamp.UTC().Format(time.RFC3339), ev.Level, ev.Action, 
				func(s string) string { if s == "" { return "-" }; return s }(ev.Username), ev.Success, 
				func(s string) string { if s == "" { return "-" }; return s }(ev.RemoteAddr), 
				func(s string) string { if s == "" { return "-" }; return s }(ev.Path), ev.Message)
		}
	}
}
