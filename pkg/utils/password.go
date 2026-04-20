package utils

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltLen             = 16
)

const DummyHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$FZ0Ztb19yPBpiSv0AvbnELtsZdrZT8ciUZn/DhZW2o0"

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("no se pudo generar la sal: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(password, encode string) (bool, error) {
	parts := strings.Split(encode, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("ivalid hash format structure")
	}
	if !strings.HasPrefix(parts[1], "argon2id") {
		return false, fmt.Errorf("unsupported algorithm variant")
	}

	var version int
	fmt.Sscanf(parts[2], "v=%d", &version)
	if version != argon2.Version {
		return false, fmt.Errorf("unsupported argon2 version %d", version)
	}

	var argonTimeReaded, argonMemoryReaded uint32
	var argonThreadsReaded uint8
	fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &argonMemoryReaded, &argonTimeReaded, &argonThreadsReaded)

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("salt decoding failed: %w", err)
	}

	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("hash decoding failed: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonTimeReaded, argonMemoryReaded, argonThreadsReaded, uint32(len(expected)))

	return subtle.ConstantTimeCompare(hash, expected) == 1, nil
}
