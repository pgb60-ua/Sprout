package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/roles"
	"sprout/pkg/store"
)

// newRolesTestServer es como newTestTLSServer pero devuelve también el RoleStore
// para poder asignar roles directamente en los tests sin pasar por la API.
func newRolesTestServer(t *testing.T) (*httptest.Server, *roles.RoleStore) {
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

	rs := roles.NewRoleStore(db)
	for _, name := range []string{roles.AdminRole, roles.DefaultRole} {
		exists, err := rs.RoleExists(name)
		if err != nil {
			t.Fatalf("RoleExists falló: %v", err)
		}
		if !exists {
			if err := rs.CreateRole(name); err != nil {
				t.Fatalf("CreateRole %q falló: %v", name, err)
			}
		}
	}

	srv := &server{
		db:            db,
		loginAttempts: make(map[string]*loginAttempt),
		sessionKeys:   make(map[string][]byte),
		pendingTOTP:   make(map[string]pendingTOTPLogin),
		pendingKey:    make(map[string]pendingKeyLogin),
		roles:         rs,
	}

	t.Cleanup(func() { _ = db.Close() })
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)

	return ts, rs
}

// registerAndLogin registra un usuario y devuelve su token.
func registerAndLogin(t *testing.T, client *http.Client, apiURL, username, password string) string {
	t.Helper()

	_, r := postJSON(t, client, apiURL, api.Request{
		Action:   api.ActionRegister,
		Username: username,
		Password: password,
	})
	if !r.Success {
		t.Fatalf("register %q falló: %s", username, r.Message)
	}

	_, r = postJSON(t, client, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: username,
		Password: password,
	})
	if !r.Success {
		t.Fatalf("login %q falló: %s", username, r.Message)
	}
	return r.Token
}

func TestServer_RegisterAssignsDefaultRole(t *testing.T) {
	ts, rs := newRolesTestServer(t)
	apiURL := ts.URL + "/api"
	httpClient := ts.Client()
	httpClient.Timeout = 2 * time.Second

	_, r := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionRegister,
		Username: "alice",
		Password: "password123",
	})
	if !r.Success {
		t.Fatalf("register falló: %s", r.Message)
	}

	ok, err := rs.HasRole("alice", roles.DefaultRole)
	if err != nil {
		t.Fatalf("HasRole falló: %v", err)
	}
	if !ok {
		t.Fatalf("el registro debería asignar el rol %q automáticamente", roles.DefaultRole)
	}
}

func TestServer_LoginIsAdminFalse(t *testing.T) {
	ts, _ := newRolesTestServer(t)
	apiURL := ts.URL + "/api"
	httpClient := ts.Client()
	httpClient.Timeout = 2 * time.Second

	_, r := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionRegister,
		Username: "alice",
		Password: "password123",
	})
	if !r.Success {
		t.Fatalf("register falló: %s", r.Message)
	}

	_, r = postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "alice",
		Password: "password123",
	})
	if !r.Success {
		t.Fatalf("login falló: %s", r.Message)
	}
	if r.IsAdmin {
		t.Fatal("un usuario sin rol admin no debería recibir IsAdmin: true")
	}
}

func TestServer_LoginIsAdminTrue(t *testing.T) {
	ts, rs := newRolesTestServer(t)
	apiURL := ts.URL + "/api"
	httpClient := ts.Client()
	httpClient.Timeout = 2 * time.Second

	_, r := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionRegister,
		Username: "alice",
		Password: "password123",
	})
	if !r.Success {
		t.Fatalf("register falló: %s", r.Message)
	}

	// Asignamos el rol admin directamente via RoleStore
	if err := rs.AssignRole("alice", roles.AdminRole); err != nil {
		t.Fatalf("AssignRole falló: %v", err)
	}

	_, r = postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionLogin,
		Username: "alice",
		Password: "password123",
	})
	if !r.Success {
		t.Fatalf("login falló: %s", r.Message)
	}
	if !r.IsAdmin {
		t.Fatal("un usuario con rol admin debería recibir IsAdmin: true en el login")
	}
}

func TestServer_RoleManagement_RequiresAdmin(t *testing.T) {
	ts, _ := newRolesTestServer(t)
	apiURL := ts.URL + "/api"
	httpClient := ts.Client()
	httpClient.Timeout = 2 * time.Second

	token := registerAndLogin(t, httpClient, apiURL, "alice", "password123")

	for _, action := range []string{
		api.ActionCreateRole,
		api.ActionDeleteRole,
		api.ActionListRoles,
		api.ActionAssignRole,
		api.ActionRemoveRole,
		api.ActionGetUserRoles,
	} {
		_, r := postJSON(t, httpClient, apiURL, api.Request{
			Action:   action,
			Username: "alice",
			Token:    token,
			Role:     "moderator",
		})
		if r.Success {
			t.Fatalf("acción %q debería rechazarse para un usuario sin rol admin", action)
		}
	}
}

func TestServer_AdminCanCreateAndDeleteRole(t *testing.T) {
	ts, rs := newRolesTestServer(t)
	apiURL := ts.URL + "/api"
	httpClient := ts.Client()
	httpClient.Timeout = 2 * time.Second

	token := registerAndLogin(t, httpClient, apiURL, "alice", "password123")
	if err := rs.AssignRole("alice", roles.AdminRole); err != nil {
		t.Fatalf("AssignRole admin falló: %v", err)
	}

	_, r := postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionCreateRole,
		Username: "alice",
		Token:    token,
		Role:     "moderator",
	})
	if !r.Success {
		t.Fatalf("createRole falló: %s", r.Message)
	}

	_, r = postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionListRoles,
		Username: "alice",
		Token:    token,
	})
	if !r.Success {
		t.Fatalf("listRoles falló: %s", r.Message)
	}
	if !slices.Contains(r.Roles, "moderator") {
		t.Fatalf("listRoles debería incluir 'moderator', obtenido: %v", r.Roles)
	}

	_, r = postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionDeleteRole,
		Username: "alice",
		Token:    token,
		Role:     "moderator",
	})
	if !r.Success {
		t.Fatalf("deleteRole falló: %s", r.Message)
	}

	_, r = postJSON(t, httpClient, apiURL, api.Request{
		Action:   api.ActionListRoles,
		Username: "alice",
		Token:    token,
	})
	if slices.Contains(r.Roles, "moderator") {
		t.Fatal("listRoles no debería incluir 'moderator' tras eliminarlo")
	}
}

func TestServer_AdminCanAssignAndRemoveRole(t *testing.T) {
	ts, rs := newRolesTestServer(t)
	apiURL := ts.URL + "/api"
	httpClient := ts.Client()
	httpClient.Timeout = 2 * time.Second

	adminToken := registerAndLogin(t, httpClient, apiURL, "alice", "password123")
	if err := rs.AssignRole("alice", roles.AdminRole); err != nil {
		t.Fatalf("AssignRole admin falló: %v", err)
	}

	registerAndLogin(t, httpClient, apiURL, "bob", "password123")

	_, r := postJSON(t, httpClient, apiURL, api.Request{
		Action:     api.ActionAssignRole,
		Username:   "alice",
		Token:      adminToken,
		TargetUser: "bob",
		Role:       roles.AdminRole,
	})
	if !r.Success {
		t.Fatalf("assignRole falló: %s", r.Message)
	}

	_, r = postJSON(t, httpClient, apiURL, api.Request{
		Action:     api.ActionGetUserRoles,
		Username:   "alice",
		Token:      adminToken,
		TargetUser: "bob",
	})
	if !r.Success {
		t.Fatalf("getUserRoles falló: %s", r.Message)
	}
	if !slices.Contains(r.Roles, roles.AdminRole) {
		t.Fatalf("bob debería tener rol admin, obtenido: %v", r.Roles)
	}

	_, r = postJSON(t, httpClient, apiURL, api.Request{
		Action:     api.ActionRemoveRole,
		Username:   "alice",
		Token:      adminToken,
		TargetUser: "bob",
		Role:       roles.AdminRole,
	})
	if !r.Success {
		t.Fatalf("removeRole falló: %s", r.Message)
	}

	_, r = postJSON(t, httpClient, apiURL, api.Request{
		Action:     api.ActionGetUserRoles,
		Username:   "alice",
		Token:      adminToken,
		TargetUser: "bob",
	})
	if slices.Contains(r.Roles, roles.AdminRole) {
		t.Fatal("bob no debería tener rol admin tras eliminarlo")
	}
}
