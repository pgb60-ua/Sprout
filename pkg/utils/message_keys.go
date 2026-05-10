package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const messageKeyFileVersion = 1

type messageKeyFile struct {
	Version   int    `json:"version"`
	KDF       string `json:"kdf"`
	Cipher    string `json:"cipher"`
	Salt      []byte `json:"salt"`
	Encrypted []byte `json:"encrypted"`
}

func messageKeyPath(username string) string {
	hash := sha256.Sum256([]byte(username))
	return filepath.Join("data", "message_keys", hex.EncodeToString(hash[:])+".key")
}

func GenerateMessageKeyPair() ([]byte, []byte, error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("error generando claves de mensajes: %w", err)
	}
	return publicKey[:], privateKey[:], nil
}

func EncodeMessagePublicKey(publicKey []byte) (string, error) {
	if len(publicKey) != 32 {
		return "", fmt.Errorf("clave publica de mensajes invalida")
	}
	return base64.RawStdEncoding.EncodeToString(publicKey), nil
}

func DecodeMessagePublicKey(encoded string) ([]byte, error) {
	publicKey, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("clave publica de mensajes invalida: %w", err)
	}
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("clave publica de mensajes invalida")
	}
	return publicKey, nil
}

func EncryptMessagePrivateKey(privateKey []byte, password, username string) error {
	if len(privateKey) != 32 {
		return fmt.Errorf("clave privada de mensajes invalida")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("error generando salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creando cifrador: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creando GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("error generando nonce: %w", err)
	}

	kf := messageKeyFile{
		Version:   messageKeyFileVersion,
		KDF:       "argon2id",
		Cipher:    "aes-256-gcm",
		Salt:      salt,
		Encrypted: gcm.Seal(nonce, nonce, privateKey, nil),
	}

	fileData, err := json.Marshal(kf)
	if err != nil {
		return fmt.Errorf("error serializando clave privada de mensajes: %w", err)
	}

	path := messageKeyPath(username)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("error creando directorio: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, fileData, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func DecryptMessagePrivateKey(password, username string) ([]byte, error) {
	path := messageKeyPath(username)
	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error leyendo clave privada de mensajes: %w", err)
	}

	var kf messageKeyFile
	if err := json.Unmarshal(fileData, &kf); err != nil {
		return nil, fmt.Errorf("archivo de clave de mensajes corrupto: %w", err)
	}
	if kf.Version != messageKeyFileVersion {
		return nil, fmt.Errorf("version de clave de mensajes no soportada: %d", kf.Version)
	}
	if kf.KDF != "argon2id" || kf.Cipher != "aes-256-gcm" {
		return nil, fmt.Errorf("algoritmo de clave de mensajes no soportado: %s/%s", kf.KDF, kf.Cipher)
	}

	key := argon2.IDKey([]byte(password), kf.Salt, 1, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creando cifrador: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creando GCM: %w", err)
	}
	if len(kf.Encrypted) < gcm.NonceSize() {
		return nil, fmt.Errorf("archivo de clave de mensajes corrupto")
	}

	nonce := kf.Encrypted[:gcm.NonceSize()]
	ciphertext := kf.Encrypted[gcm.NonceSize():]
	privateKey, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error descifrando clave privada de mensajes")
	}
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("clave privada de mensajes corrupta")
	}
	return privateKey, nil
}

func EncryptMessage(plaintext string, recipientPublicKey []byte) (string, error) {
	if len(recipientPublicKey) != 32 {
		return "", fmt.Errorf("clave publica de destinatario invalida")
	}

	var publicKey [32]byte
	copy(publicKey[:], recipientPublicKey)

	ciphertext, err := box.SealAnonymous(nil, []byte(plaintext), &publicKey, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("error cifrando mensaje: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func DecryptMessage(encodedCiphertext string, privateKey []byte) (string, error) {
	if len(privateKey) != 32 {
		return "", fmt.Errorf("clave privada de mensajes invalida")
	}

	ciphertext, err := base64.RawStdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return "", fmt.Errorf("mensaje cifrado invalido: %w", err)
	}

	var priv [32]byte
	copy(priv[:], privateKey)

	derivedPublicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("clave privada de mensajes invalida: %w", err)
	}
	var publicKey [32]byte
	copy(publicKey[:], derivedPublicKey)

	plaintext, ok := box.OpenAnonymous(nil, ciphertext, &publicKey, &priv)
	if !ok {
		return "", fmt.Errorf("no se pudo descifrar el mensaje")
	}
	return string(plaintext), nil
}
