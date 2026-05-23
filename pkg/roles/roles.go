package roles

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sprout/pkg/store"
	"time"
)

const (
	bucketRoles     = "roles"
	bucketUserRoles = "user_roles"
	DefaultRole     = "user"
	AdminRole       = "admin"
)

type Role struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type UserRoles struct {
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

type RoleStore struct {
	db store.Store
}

func NewRoleStore(db store.Store) *RoleStore {
	return &RoleStore{db: db}
}

// Funciones CRUD de roles

func (rs *RoleStore) CreateRole(name string) error {
	_, err := rs.db.Get(bucketRoles, []byte(name))
	if err == nil {
		return fmt.Errorf("el rol '%s' ya existe", name)
	}
	if !errors.Is(err, store.ErrKeyNotFound) && !errors.Is(err, store.ErrNamespaceNotFound) {
		return err
	}
	role := Role{Name: name, CreatedAt: time.Now()}
	data, err := json.Marshal(role)
	if err != nil {
		return err
	}
	return rs.db.Put(bucketRoles, []byte(name), data)
}

func (rs *RoleStore) DeleteRole(name string) error {
	_, err := rs.db.Get(bucketRoles, []byte(name))
	if errors.Is(err, store.ErrKeyNotFound) {
		return fmt.Errorf("el rol '%s' no existe", name)
	}
	if err != nil {
		return err
	}
	if err := rs.db.Delete(bucketRoles, []byte(name)); err != nil {
		return err
	}

	keys, err := rs.db.ListKeys(bucketUserRoles)
	if errors.Is(err, store.ErrNamespaceNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, k := range keys {
		ur, err := getUserRoles(rs.db, string(k))
		if err != nil {
			return err
		}
		i := slices.Index(ur.Roles, name)
		if i == -1 {
			continue
		}
		ur.Roles = slices.Delete(ur.Roles, i, i+1)
		data, err := json.Marshal(ur)
		if err != nil {
			return err
		}
		if err := rs.db.Put(bucketUserRoles, k, data); err != nil {
			return err
		}
	}
	return nil
}

func (rs *RoleStore) ListRoles() ([]Role, error) {
	keys, err := rs.db.ListKeys(bucketRoles)
	if errors.Is(err, store.ErrNamespaceNotFound) {
		return []Role{}, nil
	}
	if err != nil {
		return nil, err
	}
	var roles []Role
	for _, k := range keys {
		data, err := rs.db.Get(bucketRoles, k)
		if err != nil {
			return nil, err
		}
		var role Role
		if err := json.Unmarshal(data, &role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func (rs *RoleStore) RoleExists(name string) (bool, error) {
	_, err := rs.db.Get(bucketRoles, []byte(name))
	if errors.Is(err, store.ErrKeyNotFound) || errors.Is(err, store.ErrNamespaceNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Funcion helper

func getUserRoles(db store.Store, username string) (UserRoles, error) {
	data, err := db.Get(bucketUserRoles, []byte(username))
	if errors.Is(err, store.ErrKeyNotFound) || errors.Is(err, store.ErrNamespaceNotFound) {
		return UserRoles{Username: username, Roles: []string{}}, nil
	}
	if err != nil {
		return UserRoles{}, err
	}
	var ur UserRoles
	if err := json.Unmarshal(data, &ur); err != nil {
		return UserRoles{}, err
	}
	ur.Username = username
	return ur, nil
}

// Funciones para administrador

func (rs *RoleStore) AssignRole(username, role string) error {
	exists, err := rs.RoleExists(role)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("el rol '%s' no existe", role)
	}

	ur, err := getUserRoles(rs.db, username)
	if err != nil {
		return err
	}
	if slices.Contains(ur.Roles, role) {
		return fmt.Errorf("el usuario '%s' ya tiene el rol '%s'", username, role)
	}
	ur.Roles = append(ur.Roles, role)

	data, err := json.Marshal(ur)
	if err != nil {
		return err
	}
	return rs.db.Put(bucketUserRoles, []byte(username), data)
}

func (rs *RoleStore) RemoveRole(username, role string) error {
	ur, err := getUserRoles(rs.db, username)
	if err != nil {
		return err
	}
	i := slices.Index(ur.Roles, role)
	if i == -1 {
		return fmt.Errorf("el usuario '%s' no tiene el rol '%s'", username, role)
	}
	ur.Roles = slices.Delete(ur.Roles, i, i+1)

	data, err := json.Marshal(ur)
	if err != nil {
		return err
	}
	return rs.db.Put(bucketUserRoles, []byte(username), data)
}

// Funciones generales

func (rs *RoleStore) GetUserRoles(username string) ([]string, error) {
	ur, err := getUserRoles(rs.db, username)
	if err != nil {
		return nil, err
	}
	return ur.Roles, nil
}

func (rs *RoleStore) HasRole(username, role string) (bool, error) {
	roles, err := rs.GetUserRoles(username)
	if err != nil {
		return false, err
	}
	return slices.Contains(roles, role), nil
}

func (rs *RoleStore) HasAnyRole(username string, roles ...string) (bool, error) {
	userRoles, err := rs.GetUserRoles(username)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		if slices.Contains(userRoles, role) {
			return true, nil
		}
	}
	return false, nil
}
