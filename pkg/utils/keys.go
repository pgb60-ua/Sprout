package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const keyFileVersion = 1

type keyFile struct {
	Version   int    `json:"version"`
	KDF       string `json:"kdf"`
	Cipher    string `json:"cipher"`
	Salt      []byte `json:"salt"`
	Encrypted []byte `json:"encrypted"`
}

func keyPath(username string) string {
	hash := sha256.Sum256([]byte(username))
	return filepath.Join("data", "keys", hex.EncodeToString(hash[:])+".key")
}

func VerifySignature(publicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
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

	// Derivo clave AES de 32 bytes a partir de la contraseña
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

	// Guardo archivo en el disco
	kf := keyFile{
		Version:   keyFileVersion,
		KDF:       "argon2id",
		Cipher:    "aes-256-gcm",
		Salt:      salt,
		Encrypted: encrypted,
	}

	fileData, err := json.Marshal(kf)
	if err != nil {
		return fmt.Errorf("error serializando archivo de clave: %w", err)
	}
	path := keyPath(username)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("error creando directorio: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, fileData, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func DecryptPrivateKey(password, username string) (ed25519.PrivateKey, error) {
	// Leo el archivo
	path := keyPath(username)
	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error leyendo clave privada: %w", err)
	}

	var kf keyFile
	if err := json.Unmarshal(fileData, &kf); err != nil {
		return nil, fmt.Errorf("archivo de clave corrupto: %w", err)
	}
	if kf.Version != keyFileVersion {
		return nil, fmt.Errorf("versión de archivo de clave no soportada: %d", kf.Version)
	}
	if kf.KDF != "argon2id" || kf.Cipher != "aes-256-gcm" {
		return nil, fmt.Errorf("algoritmo no soportado: %s/%s", kf.KDF, kf.Cipher)
	}
	salt := kf.Salt
	encrypted := kf.Encrypted

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
		return nil, fmt.Errorf("error descifrando clave privada, contraseña incorrecta o achivo de clave corrupto/manipulado")
	}
	if len(sk) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("clave privada corrupta o inválida")
	}

	return ed25519.PrivateKey(sk), nil
}
