package utils

import (
	"fmt"
	"regexp"
)

const (
	minUsernameLen = 3
	maxUsernameLen = 20
	minPasswordLen = 8
)

var validUsername = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func ValidateUsername(username string) error {
	if len(username) < minUsernameLen {
		return fmt.Errorf("el nombre de usuario debe al menos %d caracteres", minUsernameLen)
	}
	if len(username) > maxUsernameLen {
		return fmt.Errorf("el nombre del usuario no puede superar los %d caracteres", maxUsernameLen)
	}
	if !validUsername.MatchString(username) {
		return fmt.Errorf("el nombre de usuario solo puede contener letras, numeros y _")
	}
	return nil
}

func ValidatePassword(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("la contraseña debe tener al menos %d caracteres", minPasswordLen)
	}
}
