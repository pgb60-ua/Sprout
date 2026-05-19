package client

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sprout/pkg/api"
)

func writeJSONResponse(w http.ResponseWriter, res api.Response) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func newAdminTestClient(t *testing.T, handler http.HandlerFunc) *client {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	t.Cleanup(ts.Close)

	caFile := writePEMCert(t, ts.Certificate())
	httpCli, err := newSecureHTTPClient(caFile)
	if err != nil {
		t.Fatalf("newSecureHTTPClient falló: %v", err)
	}
	httpCli.Timeout = 2 * time.Second

	return &client{
		log:         log.New(io.Discard, "", 0),
		httpClient:  httpCli,
		apiEndpoint: ts.URL,
		currentUser: "testuser",
		authToken:   "testtoken",
		isAdmin:     true,
	}
}

func TestClient_IsAdminInitiallyFalse(t *testing.T) {
	c := &client{}
	if c.isAdmin {
		t.Fatal("isAdmin debería ser false por defecto")
	}
}

func TestClient_SendRequest_ParsesIsAdmin(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, api.Response{Success: true, IsAdmin: true})
	}))
	defer ts.Close()

	caFile := writePEMCert(t, ts.Certificate())
	httpCli, err := newSecureHTTPClient(caFile)
	if err != nil {
		t.Fatalf("newSecureHTTPClient falló: %v", err)
	}
	httpCli.Timeout = 2 * time.Second

	c := &client{
		log:         log.New(io.Discard, "", 0),
		httpClient:  httpCli,
		apiEndpoint: ts.URL,
	}
	res := c.sendRequest(api.Request{Action: api.ActionLogin})
	if !res.IsAdmin {
		t.Fatal("sendRequest debería parsear IsAdmin: true de la respuesta del servidor")
	}
}

func TestClient_LogoutClearsIsAdmin(t *testing.T) {
	c := newAdminTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, api.Response{Success: true, Message: "sesión cerrada"})
	})

	c.logoutUser()

	if c.isAdmin {
		t.Fatal("isAdmin debería ser false tras cerrar sesión")
	}
}

func TestClient_LogoutSessionExpiryClearsIsAdmin(t *testing.T) {
	c := newAdminTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, api.Response{Success: false, SessionExpired: true})
	})

	c.logoutUser()

	if c.isAdmin {
		t.Fatal("isAdmin debería ser false tras expiración de sesión en logout")
	}
}

func TestClient_FetchDataSessionExpiryClearsIsAdmin(t *testing.T) {
	c := newAdminTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, api.Response{Success: false, SessionExpired: true})
	})

	c.fetchData()

	if c.isAdmin {
		t.Fatal("isAdmin debería ser false tras expiración de sesión en fetchData")
	}
}
