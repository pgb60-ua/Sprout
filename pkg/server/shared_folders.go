package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sprout/pkg/api"
)

const sharedFolderPrefix = "compartida_"
const sharedFolderKeyNamespace = "shared_folder_keys"

type fileAccessContext struct {
	owner       string
	storageUser string
	baseDEK     []byte
	absPath     string
	isShared    bool
	baseDir     string
	rootPath    string
}

func sharedFolderRoleName(owner string) string {
	return sharedFolderPrefix + owner
}

func sharedFolderOwnerFromPath(reqPath string) (string, bool) {
	normalized := normalizedFilePath(reqPath)
	if normalized == "" {
		return "", false
	}
	parts := strings.Split(normalized, "/")
	if len(parts) == 0 || !strings.HasPrefix(parts[0], sharedFolderPrefix) {
		return "", false
	}
	owner := strings.TrimPrefix(parts[0], sharedFolderPrefix)
	if owner == "" {
		return "", false
	}
	return owner, true
}

func sharedFolderBaseDir(owner string) string {
	return filepath.Join("data", "files", "shared", owner)
}

func sharedFolderRootPath(owner string) string {
	return sharedFolderRoleName(owner)
}

func sharedFolderRootAbsPath(owner string) string {
	return filepath.Join(sharedFolderBaseDir(owner), sharedFolderRootPath(owner))
}

func (s *server) hasSharedFolderAccess(username, owner string) (bool, error) {
	if username == owner {
		return true, nil
	}
	return s.roles.HasRole(username, sharedFolderRoleName(owner))
}

func (s *server) loadSharedFolderKey(owner string) ([]byte, error) {
	data, err := s.db.Get(sharedFolderKeyNamespace, []byte(owner))
	if err != nil {
		return nil, err
	}
	key, err := base64.RawStdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (s *server) ensureSharedFolderKey(owner string) ([]byte, error) {
	if key, err := s.loadSharedFolderKey(owner); err == nil {
		return key, nil
	}
	key := make([]byte, dekLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("no se pudo generar la clave compartida: %w", err)
	}
	if err := s.db.Put(sharedFolderKeyNamespace, []byte(owner), []byte(base64.RawStdEncoding.EncodeToString(key))); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *server) deleteSharedFolderKey(owner string) error {
	return s.db.Delete(sharedFolderKeyNamespace, []byte(owner))
}

func (s *server) resolveFileAccessContext(username, reqPath string) (fileAccessContext, error) {
	normalized := normalizedFilePath(reqPath)
	if owner, ok := sharedFolderOwnerFromPath(normalized); ok {
		allowed, err := s.hasSharedFolderAccess(username, owner)
		if err != nil {
			return fileAccessContext{}, err
		}
		if !allowed {
			return fileAccessContext{}, fmt.Errorf("acceso denegado a la carpeta compartida")
		}
		sharedKey, err := s.loadSharedFolderKey(owner)
		if err != nil {
			return fileAccessContext{}, fmt.Errorf("no se pudo cargar la clave de la carpeta compartida")
		}
		baseDir := sharedFolderBaseDir(owner)
		return fileAccessContext{
			owner:       owner,
			storageUser: owner,
			baseDEK:     sharedKey,
			absPath:     filepath.Join(baseDir, filepath.FromSlash(normalized)),
			isShared:    true,
			baseDir:     baseDir,
			rootPath:    sharedFolderRootPath(owner),
		}, nil
	}

	baseDEK, ok := s.getSessionKey(username)
	if !ok {
		return fileAccessContext{}, fmt.Errorf("Sesion inconsistente: vuelve a iniciar sesion")
	}
	baseDir := filepath.Join("data", "files", username)
	return fileAccessContext{
		owner:       username,
		storageUser: username,
		baseDEK:     baseDEK,
		absPath:     filepath.Join(baseDir, filepath.FromSlash(normalized)),
		isShared:    false,
		baseDir:     baseDir,
	}, nil
}

func (s *server) createDefaultSharedFolder(username string, dek []byte) error {
	sharedKey, err := s.ensureSharedFolderKey(username)
	if err != nil {
		return err
	}
	path, err := s.safePath(username, sharedFolderRoleName(username))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	meta, err := s.ensureFileMetadata(username, sharedKey, sharedFolderRoleName(username), info)
	if err != nil {
		return err
	}
	meta.Permissions = "rwxrwx---"
	return s.ensureSharedFolderRole(username, sharedKey, &meta)
}

func (s *server) cleanupDefaultSharedFolder(username string) error {
	_ = s.roles.DeleteRole(sharedFolderRoleName(username))
	path := sharedFolderRootAbsPath(username)
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return s.deleteSharedFolderKey(username)
}

func (s *server) loadSharedFolderMetadata(req api.Request) (api.FileMetadata, string, []byte, error) {
	if req.Path == "" {
		return api.FileMetadata{}, "", nil, fmt.Errorf("Falta el path de la carpeta compartida")
	}
	path, err := s.safePath(req.Username, req.Path)
	if err != nil {
		return api.FileMetadata{}, "", nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return api.FileMetadata{}, "", nil, fmt.Errorf("La carpeta compartida no existe")
	}
	if !info.IsDir() {
		return api.FileMetadata{}, "", nil, fmt.Errorf("La ruta no es un directorio")
	}
	dek, ok := s.getSessionKey(req.Username)
	if !ok {
		return api.FileMetadata{}, "", nil, fmt.Errorf("Sesion inconsistente: vuelve a iniciar sesion")
	}
	meta, err := s.ensureFileMetadata(req.Username, dek, req.Path, info)
	if err != nil {
		return api.FileMetadata{}, "", nil, err
	}
	if meta.Owner != req.Username {
		return api.FileMetadata{}, "", nil, fmt.Errorf("No autorizado")
	}
	return meta, path, dek, nil
}

func (s *server) ensureSharedFolderRole(username string, dek []byte, meta *api.FileMetadata) error {
	roleName := sharedFolderRoleName(meta.Owner)
	if meta.Role != roleName {
		meta.Role = roleName
		if err := s.saveFileMetadata(username, dek, *meta); err != nil {
			return err
		}
	}
	exists, err := s.roles.RoleExists(roleName)
	if err != nil {
		return err
	}
	if !exists {
		if err := s.roles.CreateRole(roleName); err != nil {
			return err
		}
	}
	hasOwner, err := s.roles.HasRole(meta.Owner, roleName)
	if err != nil {
		return err
	}
	if !hasOwner {
		if err := s.roles.AssignRole(meta.Owner, roleName); err != nil {
			return err
		}
	}
	return nil
}

func (s *server) sharedFolderAddMember(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}
	if req.TargetUser == "" {
		return api.Response{Success: false, Message: "Falta el usuario destino"}
	}
	meta, _, dek, err := s.loadSharedFolderMetadata(req)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if err := s.ensureSharedFolderRole(req.Username, dek, &meta); err != nil {
		return api.Response{Success: false, Message: "No se pudo preparar la carpeta compartida"}
	}
	roleName := sharedFolderRoleName(meta.Owner)
	if req.TargetUser == meta.Owner {
		return api.Response{Success: false, Message: "El propietario ya tiene acceso a la carpeta"}
	}
	if err := s.roles.AssignRole(req.TargetUser, roleName); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	members, err := s.roles.ListUsersByRole(roleName)
	if err != nil {
		return api.Response{Success: false, Message: "Usuario añadido, pero no se pudieron listar los miembros"}
	}
	return api.Response{Success: true, Message: "Usuario añadido a la carpeta compartida", Roles: members, FileMetadata: &meta}
}

func (s *server) sharedFolderRemoveMember(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}
	if req.TargetUser == "" {
		return api.Response{Success: false, Message: "Falta el usuario destino"}
	}
	meta, _, dek, err := s.loadSharedFolderMetadata(req)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if err := s.ensureSharedFolderRole(req.Username, dek, &meta); err != nil {
		return api.Response{Success: false, Message: "No se pudo preparar la carpeta compartida"}
	}
	roleName := sharedFolderRoleName(meta.Owner)
	if req.TargetUser == meta.Owner {
		return api.Response{Success: false, Message: "No se puede quitar el acceso al propietario"}
	}
	if err := s.roles.RemoveRole(req.TargetUser, roleName); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	members, err := s.roles.ListUsersByRole(roleName)
	if err != nil {
		return api.Response{Success: false, Message: "Usuario eliminado, pero no se pudieron listar los miembros"}
	}
	return api.Response{Success: true, Message: "Usuario eliminado de la carpeta compartida", Roles: members, FileMetadata: &meta}
}

func (s *server) sharedFolderListMembers(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}
	meta, _, dek, err := s.loadSharedFolderMetadata(req)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	if err := s.ensureSharedFolderRole(req.Username, dek, &meta); err != nil {
		return api.Response{Success: false, Message: "No se pudo preparar la carpeta compartida"}
	}
	roleName := sharedFolderRoleName(meta.Owner)
	members, err := s.roles.ListUsersByRole(roleName)
	if err != nil {
		return api.Response{Success: false, Message: "Error al listar los miembros"}
	}
	return api.Response{Success: true, Message: "Miembros obtenidos", Roles: members, FileMetadata: &meta}
}

func (s *server) cleanupSharedFolderRole(username string, meta *api.FileMetadata) error {
	if meta == nil {
		return nil
	}
	roleName := sharedFolderRoleName(meta.Owner)
	if meta.Owner != username || meta.Role != roleName {
		return nil
	}
	return s.roles.DeleteRole(roleName)
}
