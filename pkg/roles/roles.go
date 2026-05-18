package roles

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	bolt "go.etcd.io/bbolt"
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
	db *bolt.DB
}

func (rs *RoleStore) init() error {
	return rs.db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketRoles)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketUserRoles)); err != nil {
			return err
		}

		// Creo roles por defecto
		b := tx.Bucket([]byte(bucketRoles))
		for _, name := range []string{AdminRole, DefaultRole} {
			if b.Get([]byte(name)) == nil {
				role := Role{Name: name, CreatedAt: time.Now()}
				data, err := json.Marshal(role)
				if err != nil {
					return err
				}
				if err := b.Put([]byte(name), data); err != nil {
					return err
				}

			}
		}

		return nil
	})
}

func (rs *RoleStore) Close() error {
	return rs.db.Close()
}

func NewRoleStore(path string, readOnly bool) (*RoleStore, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: readOnly})
	if err != nil {
		return nil, fmt.Errorf("error abriendo %q: %w", path, err)
	}

	rs := &RoleStore{db: db}

	if !readOnly {
		if err := rs.init(); err != nil {
			db.Close()
			return nil, err
		}
	}

	return rs, nil
}

// Funciones CRUD de roles

func (rs *RoleStore) CreateRole(name string) error {
	return rs.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketRoles))
		if b == nil {
			return fmt.Errorf("bucket de roles no encontrado")
		}

		if b.Get([]byte(name)) != nil {
			return fmt.Errorf("el rol '%s' ya existe", name)
		}
		role := Role{Name: name, CreatedAt: time.Now()}
		data, err := json.Marshal(role)
		if err != nil {
			return err
		}
		return b.Put([]byte(name), data)
	})
}

func (rs *RoleStore) DeleteRole(name string) error {
	return rs.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketRoles))
		if b == nil {
			return fmt.Errorf("bucket de roles no encontrado")
		}

		if b.Get([]byte(name)) == nil {
			return fmt.Errorf("el rol '%s' no existe", name)
		}
		if err := b.Delete([]byte(name)); err != nil {
			return err
		}

		bu := tx.Bucket([]byte(bucketUserRoles))
		if bu == nil {
			return fmt.Errorf("bucket de user_roles no encontrado")
		}
		return bu.ForEach(func(k, v []byte) error {
			var ur UserRoles
			if err := json.Unmarshal(v, &ur); err != nil {
				return err
			}
			i := slices.Index(ur.Roles, name)
			if i == -1 {
				return nil
			}
			ur.Roles = slices.Delete(ur.Roles, i, i+1)
			data, err := json.Marshal(ur)
			if err != nil {
				return err
			}
			return bu.Put(k, data)
		})
	})
}

func (rs *RoleStore) ListRoles() ([]Role, error) {
	var roles []Role
	err := rs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketRoles))
		if b == nil {
			return fmt.Errorf("bucket de roles no encontrado")
		}

		return b.ForEach(func(k, v []byte) error {
			var role Role
			if err := json.Unmarshal(v, &role); err != nil {
				return err
			}
			roles = append(roles, role)
			return nil
		})
	})
	return roles, err
}

func (rs *RoleStore) RoleExists(name string) (bool, error) {
	var exists bool
	err := rs.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketRoles))
		if b == nil {
			return fmt.Errorf("bucket de roles no encontrado")
		}

		exists = b.Get([]byte(name)) != nil
		return nil
	})
	return exists, err
}

// Funcion helper

func getUserRoles(tx *bolt.Tx, username string) (UserRoles, error) {
	b := tx.Bucket([]byte(bucketUserRoles))
	if b == nil {
		return UserRoles{}, fmt.Errorf("bucket de user_roles no encontrado")
	}
	data := b.Get([]byte(username))
	if data == nil {
		return UserRoles{Username: username, Roles: []string{}}, nil
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
	return rs.db.Update(func(tx *bolt.Tx) error {
		br := tx.Bucket([]byte(bucketRoles))
		if br == nil {
			return fmt.Errorf("bucket de roles no encontrado")
		}
		if br.Get([]byte(role)) == nil {
			return fmt.Errorf("el rol '%s' no existe", role)
		}

		ur, err := getUserRoles(tx, username)
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
		b := tx.Bucket([]byte(bucketUserRoles))
		if b == nil {
			return fmt.Errorf("bucket de user_roles no encontrado")
		}
		return b.Put([]byte(username), data)
	})
}

func (rs *RoleStore) RemoveRole(username, role string) error {
	return rs.db.Update(func(tx *bolt.Tx) error {
		ur, err := getUserRoles(tx, username)
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
		b := tx.Bucket([]byte(bucketUserRoles))
		if b == nil {
			return fmt.Errorf("bucket de user_roles no encontrado")
		}
		return b.Put([]byte(username), data)
	})
}

func (rs *RoleStore) GetUserRoles(username string) ([]string, error) {
	var roles []string
	err := rs.db.View(func(tx *bolt.Tx) error {
		ur, err := getUserRoles(tx, username)
		if err != nil {
			return err
		}
		roles = ur.Roles
		return nil
	})
	return roles, err
}
