package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func NewRandomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("no se pudo generar un token aleatorio")
	}
	return hex.EncodeToString(buf), nil
}
