package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/store"
)

func newTestTLSServer(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "server.db")
	db, err := store.NewStore("bbolt", dbPath)
	if err != nil {
		t.Fatalf("no se ha podido crear la store: %v", err)
	}

	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("no se ha podido obtener el directorio actual: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("no se ha podido cambiar al directorio temporal: %v", err)
	}

	srv := &server{
		db:            db,
		loginAttempts: make(map[string]*loginAttempt),
		sessionKeys:   make(map[string][]byte),
	}

	t.Cleanup(func() { _ = db.Close() })
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts, dir, dbPath
}

func postJSON(t *testing.T, client *http.Client, url string, v any) (*http.Response, api.Response) {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fallo: %v", err)
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST fallo: %v", err)
	}
	defer resp.Body.Close()

	var ar api.Response
	_ = json.NewDecoder(resp.Body).Decode(&ar)
	return resp, ar
}

func TestServer_RegisterLoginUpdateFetchLogout(t *testing.T) {
	ts, _, _ := newTestTLSServer(t)
	apiURL := ts.URL + "/api"
	httpClient := ts.Client()
	httpClient.Timeout = 2 * time.Second

	_, r1 := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionRegister,
		Username: "alice",
		Password: "password123",
	})
	if !r1.Success {
		t.Fatalf("register fallo: %s", r1.Message)
	}

	_, r2 := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "alice",
		Password: "password123",
	})
	if !r2.Success || r2.Token == "" {
		t.Fatalf("login fallo: success=%v msg=%q token=%q", r2.Success, r2.Message, r2.Token)
	}

	_, r3 := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionUpdateData,
		Username: "alice",
		Token:    r2.Token,
		Data:     "secreto",
	})
	if !r3.Success {
		t.Fatalf("update fallo: %s", r3.Message)
	}

	_, r4 := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionFetchData,
		Username: "alice",
		Token:    r2.Token,
	})
	if !r4.Success || r4.Data != "secreto" {
		t.Fatalf("fetch fallo: success=%v msg=%q data=%q", r4.Success, r4.Message, r4.Data)
	}

	_, r5 := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionLogout,
		Username: "alice",
		Token:    r2.Token,
	})
	if !r5.Success {
		t.Fatalf("logout fallo: %s", r5.Message)
	}

	_, r6 := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionFetchData,
		Username: "alice",
		Token:    r2.Token,
	})
	if r6.Success {
		t.Fatalf("esperado fallo tras logout")
	}
}

func TestServer_UnknownFieldRejected(t *testing.T) {
	ts, _, _ := newTestTLSServer(t)
	apiURL := ts.URL + "/api"

	raw := []byte(`{"action":"register","username":"usuario","password":"password123","nope":123}`)
	client := ts.Client()
	client.Timeout = 2 * time.Second
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST fallo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status esperado 400, obtenido %d", resp.StatusCode)
	}
}

func TestServer_RejectsTrailingJSON(t *testing.T) {
	ts, _, _ := newTestTLSServer(t)
	apiURL := ts.URL + "/api"

	raw := []byte(`{"action":"register","username":"usuario","password":"password123"} {"action":"login"}`)
	client := ts.Client()
	client.Timeout = 2 * time.Second
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST fallo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status esperado 400, obtenido %d", resp.StatusCode)
	}
}

func TestServer_DataStoredEncryptedAtRest(t *testing.T) {
	ts, dir, dbPath := newTestTLSServer(t)
	apiURL := ts.URL + "/api"
	httpClient := ts.Client()
	httpClient.Timeout = 2 * time.Second

	_, registerRes := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionRegister,
		Username: "alice",
		Password: "password123",
	})
	if !registerRes.Success {
		t.Fatalf("register fallo: %s", registerRes.Message)
	}

	_, loginRes := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "alice",
		Password: "password123",
	})
	if !loginRes.Success {
		t.Fatalf("login fallo: %s", loginRes.Message)
	}

	_, updateRes := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionUpdateData,
		Username: "alice",
		Token:    loginRes.Token,
		Data:     "secreto-en-db",
	})
	if !updateRes.Success {
		t.Fatalf("update fallo: %s", updateRes.Message)
	}

	_, createRes := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionCreateFile,
		Username: "alice",
		Token:    loginRes.Token,
		Path:     "nota.txt",
		Data:     "secreto-en-fichero",
	})
	if !createRes.Success {
		t.Fatalf("createFile fallo: %s", createRes.Message)
	}

	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("no se pudo leer server.db: %v", err)
	}
	if strings.Contains(string(dbBytes), "secreto-en-db") {
		t.Fatalf("userdata quedo en claro en server.db")
	}

	fileBytes, err := os.ReadFile(filepath.Join(dir, "data", "files", "alice", "nota.txt"))
	if err != nil {
		t.Fatalf("no se pudo leer el fichero cifrado: %v", err)
	}
	if strings.Contains(string(fileBytes), "secreto-en-fichero") {
		t.Fatalf("el contenido del fichero quedo en claro en disco")
	}

	_, readRes := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionReadFile,
		Username: "alice",
		Token:    loginRes.Token,
		Path:     "nota.txt",
	})
	if !readRes.Success || readRes.Data != "secreto-en-fichero" {
		t.Fatalf("readFile fallo: success=%v msg=%q data=%q", readRes.Success, readRes.Message, readRes.Data)
	}
}
