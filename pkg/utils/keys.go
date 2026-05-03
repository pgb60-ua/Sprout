package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

func keyPath(username string) string {
	hash := sha256.Sum256([]byte(username))
	return filepath.Join("data", "keys", hex.EncodeToString(hash[:])+".key")
}

func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generando par de claves: %w", err)
	}
	return pk, sk, nil
}

func EncryptPrivateKey(sk ed25519.PrivateKey, password, username string) error {

	// Genero salt aleatorio para Argon2
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("error generando salt: %w", err)
	}

	// Derivo clave AES de 32 bytes a partir de la cotraseña
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Creo el cifrador AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creando cifrador: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creando GCM: %w", err)
	}

	// Genero nonce aleatorio
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("error generando nonce: %w", err)
	}

	// Cifro la clave privada
	encrypted := gcm.Seal(nonce, nonce, sk, nil)

	// Guardo salt + datos cifrados en disco
	fileData := append(salt, encrypted...)
	path := keyPath(username)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("error creando directorio: %w", err)
	}
	return os.WriteFile(path, fileData, 0600)
}

func DecryptPrivateKey(password, username string) (ed25519.PrivateKey, error) {
	// Leo el archivo
	path := keyPath(username)
	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error leyendo clave privada: %w", err)
	}

	// Separo salt
	if len(fileData) < 16 {
		return nil, fmt.Errorf("archivo de clave corrupto")
	}
	salt := fileData[:16]
	encrypted := fileData[16:]

	// Derivo la misma clave AES con la contraseña y el salt
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	// Creo el cifrador AES-GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creando cifrador: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creando GCM: %w", err)
	}

	// Separo nonce del contenido cifrado
	if len(encrypted) < gcm.NonceSize() {
		return nil, fmt.Errorf("archivo de clave corrupto")
	}
	nonce := encrypted[:gcm.NonceSize()]
	cipherText := encrypted[gcm.NonceSize():]

	// Descifro
	sk, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("error descifrando clave privada, contraseña incorrecta")
	}

	return ed25519.PrivateKey(sk), nil
}
