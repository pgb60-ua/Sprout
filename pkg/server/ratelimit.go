package server

import (
	"fmt"
	"time"
)

const (
	maxLoginAttempts = 3
	loginWindow      = 30 * time.Second
	loginBlockTime   = 30 * time.Second
)

type loginAttempt struct {
	Count     int
	FirstTry  time.Time
	BlockedTo time.Time
}

func (s *server) CheckLoginAllowed(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempt, ok := s.loginAttempts[username]
	if !ok {
		return nil // Nunca ha fallado
	}

	now := time.Now()

	// Si esta bloqueado
	if now.Before(attempt.BlockedTo) {
		remaining := time.Until(attempt.BlockedTo).Round(time.Second)
		return fmt.Errorf("demasiados intentos, espera %v", remaining)
	}

	// Si la ventana de tiempo paso se reinicia contador
	if now.Sub(attempt.FirstTry) > loginWindow {
		delete(s.loginAttempts, username)
	}
	return nil
}

func (s *server) RegisterLoginFailure(username string) {
	s.mu.Lock()
	// Uso defer para que se ejecute siempre que se salga de la funcion da igual como me salga
	defer s.mu.Unlock()

	now := time.Now()
	attempt, ok := s.loginAttempts[username]

	if !ok || now.Sub(attempt.FirstTry) > loginWindow {
		s.loginAttempts[username] = &loginAttempt{Count: 1, FirstTry: now}
		return
	}

	attempt.Count++
	if attempt.Count > maxLoginAttempts {
		attempt.BlockedTo = now.Add(loginBlockTime)
		attempt.Count = 0
		attempt.FirstTry = now
	}
}

func (s *server) ClearLoginFailures(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.loginAttempts, username)
}
