package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/xts"
)

const (
	cryptoNamespace = "crypto"

	cryptoVersion = 1

	kekSaltLen = 16
	dekLen     = 32

	gcmNonceLen   = 12
	fileHeaderLen = 12
	fileSectorLen = 4096

	kekArgonTime    uint32 = 3
	kekArgonMemory  uint32 = 64 * 1024
	kekArgonThreads uint8  = 4
	kekLen          uint32 = 32

	fileMagic = "SPRT"
)

type userCryptoMetadata struct {
	Version      int    `json:"version"`
	KEKSalt      string `json:"kek_salt"`
	WrappedDEK   string `json:"wrapped_dek"`
	WrappedNonce string `json:"wrapped_nonce"`
}

type gcmBlob struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func generateUserCryptoMetadata(password string) (*userCryptoMetadata, []byte, error) {
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("no se pudo generar DEK: %w", err)
	}

	salt := make([]byte, kekSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("no se pudo generar salt de KEK: %w", err)
	}

	kek := deriveKEK(password, salt)
	wrappedDEK, nonce, err := encryptWithGCM(kek, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("no se pudo cifrar la DEK: %w", err)
	}

	return &userCryptoMetadata{
		Version:      cryptoVersion,
		KEKSalt:      base64.RawStdEncoding.EncodeToString(salt),
		WrappedDEK:   base64.RawStdEncoding.EncodeToString(wrappedDEK),
		WrappedNonce: base64.RawStdEncoding.EncodeToString(nonce),
	}, dek, nil
}

func unwrapUserDEK(password string, metaBytes []byte) ([]byte, error) {
	var meta userCryptoMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("metadatos criptograficos invalidos: %w", err)
	}
	if meta.Version != cryptoVersion {
		return nil, fmt.Errorf("version criptografica no soportada: %d", meta.Version)
	}

	salt, err := base64.RawStdEncoding.DecodeString(meta.KEKSalt)
	if err != nil {
		return nil, fmt.Errorf("salt de KEK invalida: %w", err)
	}
	wrappedDEK, err := base64.RawStdEncoding.DecodeString(meta.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("DEK cifrada invalida: %w", err)
	}
	nonce, err := base64.RawStdEncoding.DecodeString(meta.WrappedNonce)
	if err != nil {
		return nil, fmt.Errorf("nonce de DEK invalido: %w", err)
	}

	kek := deriveKEK(password, salt)
	dek, err := decryptWithGCM(kek, nonce, wrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("no se pudo descifrar la DEK: %w", err)
	}
	return dek, nil
}

func deriveKEK(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, kekArgonTime, kekArgonMemory, kekArgonThreads, kekLen)
}

func deriveSubkey(baseKey []byte, context string, size int) ([]byte, error) {
	reader := hkdf.New(sha256.New, baseKey, nil, []byte(context))
	key := make([]byte, size)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("no se pudo derivar subclave %q: %w", context, err)
	}
	return key, nil
}

func encryptUserdata(baseDEK, plaintext []byte) ([]byte, error) {
	key, err := deriveSubkey(baseDEK, "userdata", dekLen)
	if err != nil {
		return nil, err
	}
	ciphertext, nonce, err := encryptWithGCM(key, plaintext)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(gcmBlob{
		Version:    cryptoVersion,
		Nonce:      base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return nil, fmt.Errorf("no se pudo serializar userdata cifrada: %w", err)
	}
	return data, nil
}

func decryptUserdata(baseDEK, blobBytes []byte) ([]byte, error) {
	var blob gcmBlob
	if err := json.Unmarshal(blobBytes, &blob); err != nil {
		return nil, fmt.Errorf("userdata cifrada invalida: %w", err)
	}
	if blob.Version != cryptoVersion {
		return nil, fmt.Errorf("version de userdata no soportada: %d", blob.Version)
	}

	nonce, err := base64.RawStdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce de userdata invalido: %w", err)
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ciphertext de userdata invalido: %w", err)
	}

	key, err := deriveSubkey(baseDEK, "userdata", dekLen)
	if err != nil {
		return nil, err
	}
	return decryptWithGCM(key, nonce, ciphertext)
}

func encryptFileData(baseDEK []byte, path string, plaintext []byte) ([]byte, error) {
	key, err := deriveSubkey(baseDEK, "files:"+path, 64)
	if err != nil {
		return nil, err
	}

	xtsCipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, fmt.Errorf("no se pudo inicializar XTS: %w", err)
	}

	header := make([]byte, fileHeaderLen)
	copy(header[:4], []byte(fileMagic))
	binary.BigEndian.PutUint32(header[4:8], cryptoVersion)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(plaintext)))

	var out bytes.Buffer
	out.Write(header)

	for sectorNum, offset := uint64(0), 0; offset < len(plaintext); sectorNum, offset = sectorNum+1, offset+fileSectorLen {
		end := minInt(offset+fileSectorLen, len(plaintext))
		sector := plaintext[offset:end]
		paddedLen := roundUpToBlock(len(sector))
		padded := make([]byte, paddedLen)
		copy(padded, sector)

		ciphertext := make([]byte, paddedLen)
		xtsCipher.Encrypt(ciphertext, padded, sectorNum)
		out.Write(ciphertext)
	}

	return out.Bytes(), nil
}

func decryptFileData(baseDEK []byte, path string, encrypted []byte) ([]byte, error) {
	if len(encrypted) < fileHeaderLen {
		return nil, fmt.Errorf("fichero cifrado invalido: cabecera incompleta")
	}
	if string(encrypted[:4]) != fileMagic {
		return nil, fmt.Errorf("fichero cifrado invalido: cabecera desconocida")
	}

	version := binary.BigEndian.Uint32(encrypted[4:8])
	if version != cryptoVersion {
		return nil, fmt.Errorf("version de fichero cifrado no soportada: %d", version)
	}

	plainLen := int(binary.BigEndian.Uint32(encrypted[8:12]))
	ciphertext := encrypted[fileHeaderLen:]

	expectedCipherLen := 0
	for offset := 0; offset < plainLen; offset += fileSectorLen {
		sectorLen := minInt(fileSectorLen, plainLen-offset)
		expectedCipherLen += roundUpToBlock(sectorLen)
	}
	if len(ciphertext) != expectedCipherLen {
		return nil, fmt.Errorf("fichero cifrado invalido: longitud inesperada")
	}

	key, err := deriveSubkey(baseDEK, "files:"+path, 64)
	if err != nil {
		return nil, err
	}

	xtsCipher, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, fmt.Errorf("no se pudo inicializar XTS: %w", err)
	}

	plaintext := make([]byte, 0, plainLen)
	cipherOffset := 0
	for sectorNum, plainOffset := uint64(0), 0; plainOffset < plainLen; sectorNum, plainOffset = sectorNum+1, plainOffset+fileSectorLen {
		sectorLen := minInt(fileSectorLen, plainLen-plainOffset)
		paddedLen := roundUpToBlock(sectorLen)
		sectorCiphertext := ciphertext[cipherOffset : cipherOffset+paddedLen]
		sectorPlaintext := make([]byte, paddedLen)
		xtsCipher.Decrypt(sectorPlaintext, sectorCiphertext, sectorNum)
		plaintext = append(plaintext, sectorPlaintext[:sectorLen]...)
		cipherOffset += paddedLen
	}

	return plaintext, nil
}

func encryptWithGCM(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("no se pudo crear AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("no se pudo crear GCM: %w", err)
	}

	nonce := make([]byte, gcmNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("no se pudo generar nonce: %w", err)
	}

	return aead.Seal(nil, nonce, plaintext, nil), nonce, nil
}

func decryptWithGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("no se pudo crear AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("no se pudo crear GCM: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("fallo al descifrar GCM: %w", err)
	}
	return plaintext, nil
}

func roundUpToBlock(n int) int {
	if n == 0 {
		return aes.BlockSize
	}
	if n%aes.BlockSize == 0 {
		return n
	}
	return n + (aes.BlockSize - n%aes.BlockSize)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
