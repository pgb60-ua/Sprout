package roles

import (
	"path/filepath"
	"slices"
	"sprout/pkg/store"
	"testing"
)

func newTestRoleStore(t *testing.T) *RoleStore {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "roles.db")

	db, err := store.NewStore("bbolt", path)
	if err != nil {
		t.Fatalf("no se ha podido crear la store de pruebas: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return NewRoleStore(db)
}

func TestRoleStore_CreateRole(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.CreateRole("moderator"); err != nil {
		t.Fatalf("CreateRole falló: %v", err)
	}

	exists, err := rs.RoleExists("moderator")
	if err != nil {
		t.Fatalf("RoleExists falló: %v", err)
	}
	if !exists {
		t.Fatal("el rol 'moderator' debería existir tras crearlo")
	}
}

func TestRoleStore_CreateRoleDuplicate(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.CreateRole("moderator"); err != nil {
		t.Fatalf("primera CreateRole falló: %v", err)
	}
	if err := rs.CreateRole("moderator"); err == nil {
		t.Fatal("se esperaba error al crear un rol duplicado")
	}
}

func TestRoleStore_DeleteRole(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.CreateRole("temporal"); err != nil {
		t.Fatalf("CreateRole falló: %v", err)
	}
	if err := rs.DeleteRole("temporal"); err != nil {
		t.Fatalf("DeleteRole falló: %v", err)
	}

	exists, err := rs.RoleExists("temporal")
	if err != nil {
		t.Fatalf("RoleExists falló: %v", err)
	}
	if exists {
		t.Fatal("el rol 'temporal' no debería existir tras eliminarlo")
	}
}

func TestRoleStore_DeleteRoleNotFound(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.DeleteRole("noexiste"); err == nil {
		t.Fatal("se esperaba error al eliminar un rol inexistente")
	}
}

func TestRoleStore_ListRoles(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.CreateRole("moderator"); err != nil {
		t.Fatalf("CreateRole falló: %v", err)
	}

	roles, err := rs.ListRoles()
	if err != nil {
		t.Fatalf("ListRoles falló: %v", err)
	}

	found := make(map[string]bool)
	for _, r := range roles {
		found[r.Name] = true
	}

	if !found["moderator"] {
		t.Fatal("ListRoles debería incluir el rol 'moderator'")
	}
}

func TestRoleStore_RoleExists(t *testing.T) {
	rs := newTestRoleStore(t)

	exists, err := rs.RoleExists("noexiste")
	if err != nil {
		t.Fatalf("RoleExists falló: %v", err)
	}
	if exists {
		t.Fatal("RoleExists debería devolver false para un rol inexistente")
	}

	if err := rs.CreateRole("moderator"); err != nil {
		t.Fatalf("CreateRole falló: %v", err)
	}

	exists, err = rs.RoleExists("moderator")
	if err != nil {
		t.Fatalf("RoleExists falló: %v", err)
	}
	if !exists {
		t.Fatal("RoleExists debería devolver true para un rol existente")
	}
}

func TestRoleStore_PersistsOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.db")

	{
		db, err := store.NewStore("bbolt", path)
		if err != nil {
			t.Fatalf("open falló: %v", err)
		}
		rs := NewRoleStore(db)
		if err := rs.CreateRole("moderator"); err != nil {
			_ = db.Close()
			t.Fatalf("CreateRole falló: %v", err)
		}
		_ = db.Close()
	}

	{
		db, err := store.NewStore("bbolt", path)
		if err != nil {
			t.Fatalf("re-open falló: %v", err)
		}
		defer db.Close()
		rs := NewRoleStore(db)

		exists, err := rs.RoleExists("moderator")
		if err != nil {
			t.Fatalf("RoleExists tras re-open falló: %v", err)
		}
		if !exists {
			t.Fatal("el rol 'moderator' debería persistir tras cerrar y reabrir la store")
		}
	}
}

func TestRoleStore_AssignRole(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.CreateRole(DefaultRole); err != nil {
		t.Fatalf("CreateRole falló: %v", err)
	}
	if err := rs.AssignRole("carlos", DefaultRole); err != nil {
		t.Fatalf("AssignRole falló: %v", err)
	}

	roles, err := rs.GetUserRoles("carlos")
	if err != nil {
		t.Fatalf("GetUserRoles falló: %v", err)
	}
	if !slices.Contains(roles, DefaultRole) {
		t.Fatalf("se esperaba el rol %q asignado", DefaultRole)
	}
}

func TestRoleStore_AssignRoleNotFound(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.AssignRole("carlos", "noexiste"); err == nil {
		t.Fatal("se esperaba error al asignar un rol inexistente")
	}
}

func TestRoleStore_AssignRoleDuplicate(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.CreateRole(DefaultRole); err != nil {
		t.Fatalf("CreateRole falló: %v", err)
	}
	if err := rs.AssignRole("carlos", DefaultRole); err != nil {
		t.Fatalf("primera AssignRole falló: %v", err)
	}
	if err := rs.AssignRole("carlos", DefaultRole); err == nil {
		t.Fatal("se esperaba error al asignar un rol duplicado")
	}
}

func TestRoleStore_RemoveRole(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.CreateRole(DefaultRole); err != nil {
		t.Fatalf("CreateRole falló: %v", err)
	}
	if err := rs.AssignRole("carlos", DefaultRole); err != nil {
		t.Fatalf("AssignRole falló: %v", err)
	}
	if err := rs.RemoveRole("carlos", DefaultRole); err != nil {
		t.Fatalf("RemoveRole falló: %v", err)
	}

	roles, err := rs.GetUserRoles("carlos")
	if err != nil {
		t.Fatalf("GetUserRoles falló: %v", err)
	}
	if slices.Contains(roles, DefaultRole) {
		t.Fatalf("el rol %q no debería estar tras eliminarlo", DefaultRole)
	}
}

func TestRoleStore_RemoveRoleNotAssigned(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.RemoveRole("carlos", DefaultRole); err == nil {
		t.Fatal("se esperaba error al quitar un rol no asignado")
	}
}

func TestRoleStore_GetUserRolesEmpty(t *testing.T) {
	rs := newTestRoleStore(t)

	roles, err := rs.GetUserRoles("carlos")
	if err != nil {
		t.Fatalf("GetUserRoles falló: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("se esperaba slice vacío para usuario sin roles, obtenido: %v", roles)
	}
}

func TestRoleStore_UserRolesPersistsOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roles.db")

	{
		db, err := store.NewStore("bbolt", path)
		if err != nil {
			t.Fatalf("open falló: %v", err)
		}
		rs := NewRoleStore(db)
		if err := rs.CreateRole(DefaultRole); err != nil {
			_ = db.Close()
			t.Fatalf("CreateRole falló: %v", err)
		}
		if err := rs.AssignRole("carlos", DefaultRole); err != nil {
			_ = db.Close()
			t.Fatalf("AssignRole falló: %v", err)
		}
		_ = db.Close()
	}

	{
		db, err := store.NewStore("bbolt", path)
		if err != nil {
			t.Fatalf("re-open falló: %v", err)
		}
		defer db.Close()
		rs := NewRoleStore(db)

		roles, err := rs.GetUserRoles("carlos")
		if err != nil {
			t.Fatalf("GetUserRoles tras re-open falló: %v", err)
		}
		if !slices.Contains(roles, DefaultRole) {
			t.Fatalf("el rol %q debería persistir tras cerrar y reabrir la store", DefaultRole)
		}
	}
}

func TestRoleStore_DeleteRoleCleansUserRoles(t *testing.T) {
	rs := newTestRoleStore(t)

	if err := rs.CreateRole("moderator"); err != nil {
		t.Fatalf("CreateRole falló: %v", err)
	}
	if err := rs.AssignRole("carlos", "moderator"); err != nil {
		t.Fatalf("AssignRole falló: %v", err)
	}
	if err := rs.DeleteRole("moderator"); err != nil {
		t.Fatalf("DeleteRole falló: %v", err)
	}

	roles, err := rs.GetUserRoles("carlos")
	if err != nil {
		t.Fatalf("GetUserRoles falló: %v", err)
	}
	if slices.Contains(roles, "moderator") {
		t.Fatal("el rol 'moderator' no debería aparecer en user_roles tras ser eliminado")
	}
}
