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
	meta, err := s.loadFileMetadata(username, dek, path, info)
	if err == nil {
		return meta, nil
	}
	if !errors.Is(err, store.ErrNamespaceNotFound) && !errors.Is(err, store.ErrKeyNotFound) {
		return api.FileMetadata{}, err
	}

	now := time.Now().UTC()
	permissions := "rw-------"
	if info.IsDir() {
		permissions = "rwx------"
	}
	meta = mergeFileMetadata(path, api.FileMetadata{
		Path:        normalizedFilePath(path),
		Owner:       username,
		Permissions: permissions,
		CreatedAt:   now,
		ModifiedAt:  now,
		Platform:    runtime.GOOS,
	}, info)
	if err := s.saveFileMetadata(username, dek, meta); err != nil {
		return api.FileMetadata{}, err
	}
	return meta, nil
}

func (s *server) deleteFileMetadata(username string, dek []byte, path string) error {
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

func (s *server) deleteFileMetadataTree(username string, dek []byte, rootAbsPath string) error {
	baseDir := filepath.Join("data", "files", username)
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
	if len(meta.Permissions) < 3 {
		return false
	}
	switch permission {
	case 'r':
		return meta.Permissions[0] == 'r'
	case 'w':
		return meta.Permissions[1] == 'w'
	case 'x':
		return meta.Permissions[2] == 'x'
	default:
		return false
	}
}

func parentFilePath(path string) string {
	normalized := normalizedFilePath(path)
	parent := filepath.ToSlash(filepath.Dir(normalized))
	if parent == "." {
		return ""
	}
	return parent
}

func (s *server) requireFilePermission(username string, dek []byte, path string, info os.FileInfo, permission byte) api.Response {
	meta, err := s.ensureFileMetadata(username, dek, path, info)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener metadatos"}
	}
	if !hasLogicalPermission(meta, permission) {
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
	meta, err := s.ensureFileMetadata(username, dek, parentPath, info)
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener metadatos del directorio padre"}
	}
	if !hasLogicalPermission(meta, 'w') || !hasLogicalPermission(meta, 'x') {
		return api.Response{Success: false, Message: "Permiso denegado"}
	}
	return api.Response{Success: true, FileMetadata: &meta}
}
