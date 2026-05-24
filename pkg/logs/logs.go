package logs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"sprout/pkg/remotecommon"
)

func Run() {
	endpoint, caFile := "https://localhost:8081/logs", "data/certs/ca-cert.pem"
	entries := make(map[string][]byte)

	cli, err := remotecommon.NewHTTPClient(endpoint, caFile, 3*time.Second)
	if err != nil {
		fmt.Printf("No se pudo leer la base de logs remota ni crear el cliente HTTP: %v\n", err)
		return
	}
	req, err := http.NewRequest("GET", endpoint+"?limit=50", nil)
	if err != nil {
		fmt.Printf("Error preparando petición HTTP: %v\n", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+remotecommon.GetSharedSecret())
	resp, err := cli.Do(req)
	if err != nil {
		fmt.Printf("No se pudo obtener logs mediante HTTP: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		fmt.Printf("El servidor remoto de logs respondió con un código de error: %s\n", resp.Status)
		return
	}
	var evs []remotecommon.LogEvent
	if err := json.NewDecoder(resp.Body).Decode(&evs); err != nil {
		fmt.Printf("Error decodificando los logs desde servidor: %v\n", err)
		return
	}
	for i, ev := range evs {
		raw, marshalErr := json.Marshal(ev)
		if marshalErr != nil {
			fmt.Printf("Error serializando evento log internamente: %v\n", marshalErr)
			continue
		}
		entries[fmt.Sprintf("%03d-%s", i, ev.Timestamp.UTC().Format(time.RFC3339Nano))] = raw
	}
	
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		fmt.Println("No hay logs remotos guardados.")
		return
	}
	sort.Strings(keys)
	if len(keys) > 50 {
		keys = keys[len(keys)-50:]
	}
	for _, k := range keys {
		var ev remotecommon.LogEvent
		if err := json.Unmarshal(entries[k], &ev); err != nil {
			fmt.Printf("Error deserializando log local: %v\n", err)
			continue
		}
		fmt.Printf("%s level=%s action=%s user=%s success=%t ip=%s path=%s msg=%s\n",
			ev.Timestamp.UTC().Format(time.RFC3339),
			ev.Level,
			ev.Action, 
			valOr(ev.Username, "-"),
			ev.Success, 
			valOr(ev.RemoteAddr, "-"), 
			valOr(ev.Path, "-"),
			ev.Message)
	}
}

func valOr(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}
