package roles

import (
	"encoding/json"
	"fmt"
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
		return b.Delete([]byte(name))
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
