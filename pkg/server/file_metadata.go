package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/store"
)

const fileMetadataNamespace = "file_metadata"

func normalizedFilePath(reqPath string) string {
	cleaned := filepath.Clean(strings.TrimSpace(reqPath))
	if cleaned == "." {
		return ""
	}
	return filepath.ToSlash(cleaned)
}

func fileMetadataKey(dek []byte, username, path string) ([]byte, error) {
	indexKey, err := deriveSubkey(dek, "file_metadata_index", dekLen)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, indexKey)
	_, _ = mac.Write([]byte(normalizedFilePath(path)))
	return []byte(username + "\x00" + hex.EncodeToString(mac.Sum(nil))), nil
}

func encryptFileMetadata(dek []byte, path string, meta api.FileMetadata) ([]byte, error) {
	plaintext, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("no se pudo serializar metadatos: %w", err)
	}

	key, err := deriveSubkey(dek, "file_metadata:"+normalizedFilePath(path), dekLen)
	if err != nil {
		return nil, err
	}

	ciphertext, nonce, err := encryptWithGCM(key, plaintext)
	if err != nil {
		return nil, err
	}

	blob, err := json.Marshal(gcmBlob{
		Version:    cryptoVersion,
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return nil, fmt.Errorf("no se pudo serializar metadatos cifrados: %w", err)
	}
	return blob, nil
}

func decryptFileMetadata(dek []byte, path string, data []byte) (api.FileMetadata, error) {
	var blob gcmBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return api.FileMetadata{}, fmt.Errorf("metadatos cifrados invalidos: %w", err)
	}
	if blob.Version != cryptoVersion {
		return api.FileMetadata{}, fmt.Errorf("version de metadatos no soportada: %d", blob.Version)
	}

	nonce, err := base64.RawStdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return api.FileMetadata{}, fmt.Errorf("nonce de metadatos invalido: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		return api.FileMetadata{}, fmt.Errorf("ciphertext de metadatos invalido: %w", err)
	}

	key, err := deriveSubkey(dek, "file_metadata:"+normalizedFilePath(path), dekLen)
	if err != nil {
		return api.FileMetadata{}, err
	}
	plaintext, err := decryptWithGCM(key, nonce, ciphertext)
	if err != nil {
		return api.FileMetadata{}, err
	}

	var meta api.FileMetadata
	if err := json.Unmarshal(plaintext, &meta); err != nil {
		return api.FileMetadata{}, fmt.Errorf("metadatos invalidos: %w", err)
	}
	return meta, nil
}

func (s *server) loadFileMetadata(username string, dek []byte, path string, info os.FileInfo) (api.FileMetadata, error) {
	if normalizedFilePath(path) == "" {
		_ = s.deleteRootFileMetadata(username, dek)
		return rootFileMetadata(username), nil
	}
	key, err := fileMetadataKey(dek, username, path)
	if err != nil {
		return api.FileMetadata{}, err
	}
	data, err := s.db.Get(fileMetadataNamespace, key)
	if err != nil {
		return api.FileMetadata{}, err
	}

	meta, err := decryptFileMetadata(dek, path, data)
	if err != nil {
		return api.FileMetadata{}, err
	}
	return mergeFileMetadata(path, meta, info), nil
}

func (s *server) saveFileMetadata(username string, dek []byte, meta api.FileMetadata) error {
	meta.Path = normalizedFilePath(meta.Path)
	if meta.Path == "" {
		return nil
	}
	key, err := fileMetadataKey(dek, username, meta.Path)
	if err != nil {
		return err
	}
	data, err := encryptFileMetadata(dek, meta.Path, meta)
	if err != nil {
		return err
	}
	return s.db.Put(fileMetadataNamespace, key, data)
}

func (s *server) ensureFileMetadata(username string, dek []byte, path string, info os.FileInfo) (api.FileMetadata, error) {
	if normalizedFilePath(path) == "" {
		_ = s.deleteRootFileMetadata(username, dek)
		return rootFileMetadata(username), nil
	}
	meta, err := s.loadFileMetadata(username, dek, path, info)
	if err == nil {
		return meta, nil
	}
	if !errors.Is(err, store.ErrNamespaceNotFound) && !errors.Is(err, store.ErrKeyNotFound) {
		return api.FileMetadata{}, err
	}

	now := time.Now().UTC()
	// Default permissions: owner-only. If the path belongs to a shared folder
	// owned by `username`, grant group (role) access by default so members
	// of the shared folder can access newly created entries.
	permissions := "rw-------"
	if info.IsDir() {
		permissions = "rwx------"
	}
	if _, ok := sharedFolderOwnerFromPath(path); ok {
		// For any path inside a shared folder, make directories and files
		// group-accessible by default so members can access items created
		// inside the shared area regardless of who created them.
		if info.IsDir() {
			permissions = "rwxrwx---"
		} else {
			permissions = "rw-rw----"
		}
	}
	meta = mergeFileMetadata(path, api.FileMetadata{
		Path:        normalizedFilePath(path),
		Owner:       username,
		Permissions: permissions,
		CreatedAt:   now,
		ModifiedAt:  now,
		Platform:    runtime.GOOS,
	}, info)
	if owner, ok := sharedFolderOwnerFromPath(path); ok {
		meta.Role = sharedFolderRoleName(owner)
	}
	if err := s.saveFileMetadata(username, dek, meta); err != nil {
		return api.FileMetadata{}, err
	}
	return meta, nil
}

func (s *server) deleteFileMetadata(username string, dek []byte, path string) error {
	if normalizedFilePath(path) == "" {
		return nil
	}
	key, err := fileMetadataKey(dek, username, path)
	if err != nil {
		return err
	}
	if err := s.db.Delete(fileMetadataNamespace, key); err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) || errors.Is(err, store.ErrKeyNotFound) {
			return nil
		}
		return err
	}
	return nil
}

func (s *server) deleteRootFileMetadata(username string, dek []byte) error {
	key, err := fileMetadataKey(dek, username, "")
	if err != nil {
		return err
	}
	if err := s.db.Delete(fileMetadataNamespace, key); err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) || errors.Is(err, store.ErrKeyNotFound) {
			return nil
		}
		return err
	}
	return nil
}

func (s *server) deleteFileMetadataTree(username string, dek []byte, rootAbsPath string, baseDir string) error {
	baseDirAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return err
	}

	return filepath.WalkDir(rootAbsPath, func(path string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		absPath, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(baseDirAbs, absPath)
		if err != nil {
			return err
		}
		if rel == "." {
			rel = ""
		}
		return s.deleteFileMetadata(username, dek, rel)
	})
}

func mergeFileMetadata(path string, meta api.FileMetadata, info os.FileInfo) api.FileMetadata {
	meta.Path = normalizedFilePath(path)
	meta.Name = info.Name()
	meta.IsDir = info.IsDir()
	meta.Size = info.Size()
	if meta.Owner == "" {
		meta.Owner = ""
	}
	if meta.Platform == "" {
		meta.Platform = runtime.GOOS
	}
	return meta
}

func validFilePermissions(permissions string) bool {
	if len(permissions) != 9 {
		return false
	}
	for i, r := range permissions {
		switch i % 3 {
		case 0:
			if r != 'r' && r != '-' {
				return false
			}
		case 1:
			if r != 'w' && r != '-' {
				return false
			}
		case 2:
			if r != 'x' && r != '-' {
				return false
			}
		}
	}
	return true
}

func hasLogicalPermission(meta api.FileMetadata, permission byte) bool {
	return hasPermissionAt(meta.Permissions, 0, permission)
}

func hasPermissionAt(permissions string, offset int, permission byte) bool {
	if len(permissions) != 9 || offset < 0 || offset+2 >= len(permissions) {
		return false
	}
	switch permission {
	case 'r':
		return permissions[offset] == 'r'
	case 'w':
		return permissions[offset+1] == 'w'
	case 'x':
		return permissions[offset+2] == 'x'
	default:
		return false
	}
}

func (s *server) hasLogicalPermissionForUser(username string, meta api.FileMetadata, permission byte) bool {
	offset := 6
	if username == meta.Owner {
		offset = 0
	} else if meta.Role != "" {
		ok, err := s.roles.HasRole(username, meta.Role)
		if err == nil && ok {
			offset = 3
		}
	}
	return hasPermissionAt(meta.Permissions, offset, permission)
}

func parentFilePath(path string) string {
	normalized := normalizedFilePath(path)
	parent := filepath.ToSlash(filepath.Dir(normalized))
	if parent == "." {
		return ""
	}
	return parent
}

func rootFileMetadata(username string) api.FileMetadata {
	now := time.Now().UTC()
	return api.FileMetadata{
		Path:        "",
		Name:        username,
		IsDir:       true,
		Owner:       username,
		Permissions: "rwx------",
		CreatedAt:   now,
		ModifiedAt:  now,
		Platform:    runtime.GOOS,
	}
}

func pathPrefixes(path string) []string {
	normalized := normalizedFilePath(path)
	if normalized == "" {
		return nil
	}
	parts := strings.Split(normalized, "/")
	prefixes := make([]string, 0, len(parts))
	for i := range parts {
		prefixes = append(prefixes, strings.Join(parts[:i+1], "/"))
	}
	return prefixes
}

func (s *server) loadPermissionTree(username string, _ []byte, path string, includeTarget bool) ([]api.FileMetadata, error) {
	normalized := normalizedFilePath(path)
	ctx, err := s.resolveFileAccessContext(username, normalized)
	if err != nil {
		return nil, err
	}

	if ctx.isShared {
		rootInfo, err := os.Stat(sharedFolderRootAbsPath(ctx.owner))
		if err != nil {
			return nil, err
		}
		rootMeta, err := s.ensureFileMetadata(ctx.storageUser, ctx.baseDEK, ctx.rootPath, rootInfo)
		if err != nil {
			return nil, err
		}
		tree := []api.FileMetadata{rootMeta}
		prefixes := pathPrefixes(normalized)
		if len(prefixes) > 0 && prefixes[0] == ctx.rootPath {
			prefixes = prefixes[1:]
		}
		if !includeTarget && len(prefixes) > 0 {
			prefixes = prefixes[:len(prefixes)-1]
		}
		for _, prefix := range prefixes {
			absPath := filepath.Join(ctx.baseDir, filepath.FromSlash(prefix))
			info, err := os.Stat(absPath)
			if err != nil {
				return nil, err
			}
			meta, err := s.ensureFileMetadata(ctx.storageUser, ctx.baseDEK, prefix, info)
			if err != nil {
				return nil, err
			}
			tree = append(tree, meta)
		}
		return tree, nil
	}

	tree := []api.FileMetadata{rootFileMetadata(username)}
	prefixes := pathPrefixes(normalized)
	if !includeTarget && len(prefixes) > 0 {
		prefixes = prefixes[:len(prefixes)-1]
	}
	for _, prefix := range prefixes {
		absPath := filepath.Join(ctx.baseDir, filepath.FromSlash(prefix))
		info, err := os.Stat(absPath)
		if err != nil {
			return nil, err
		}
		meta, err := s.ensureFileMetadata(ctx.storageUser, ctx.baseDEK, prefix, info)
		if err != nil {
			return nil, err
		}
		tree = append(tree, meta)
	}
	return tree, nil
}

func (s *server) hasPermissionThroughTree(username string, tree []api.FileMetadata, permission byte) bool {
	for _, meta := range tree {
		if !s.hasLogicalPermissionForUser(username, meta, permission) {
			return false
		}
	}
	return true
}

func (s *server) requirePathPermission(username string, dek []byte, path string, includeTarget bool, permission byte) api.Response {
	tree, err := s.loadPermissionTree(username, dek, path, includeTarget)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener permisos del arbol"}
	}
	if !s.hasPermissionThroughTree(username, tree, permission) {
		return api.Response{Success: false, Message: "Permiso denegado"}
	}
	return api.Response{Success: true}
}

func (s *server) requireFilePermission(username string, dek []byte, path string, info os.FileInfo, permission byte) api.Response {
	meta, err := s.ensureFileMetadata(username, dek, path, info)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener metadatos"}
	}
	if !s.hasLogicalPermissionForUser(username, meta, permission) {
		return api.Response{Success: false, Message: "Permiso denegado"}
	}
	return api.Response{Success: true, FileMetadata: &meta}
}

func (s *server) requireParentDirWrite(username string, dek []byte, childPath string) api.Response {
	parentPath := parentFilePath(childPath)
	parentAbsPath, err := s.safePath(username, parentPath)
	if err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	info, err := os.Stat(parentAbsPath)
	if err != nil || !info.IsDir() {
		return api.Response{Success: false, Message: "El directorio padre no existe"}
	}
	_ = info
	return s.requirePathPermission(username, dek, parentPath, true, 'w')
}
