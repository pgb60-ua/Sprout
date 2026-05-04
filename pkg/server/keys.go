package server

import (
	"encoding/json"
	"sprout/pkg/api"
	"sprout/pkg/utils"
	"time"
)

type keyAuthData struct {
	Enabled   bool   `json:"enabled"`
	PublicKey []byte `json:"public_key"`
}

type pendingKeyLogin struct {
	Username  string
	Challenge []byte
	ExpiresAt time.Time
}

func (s *server) getKeyAuthData(username string) (keyAuthData, error) {
	data, err := s.db.Get("keys", []byte(username))
	if err != nil {
		return keyAuthData{}, err
	}

	var td keyAuthData
	if err := json.Unmarshal(data, &td); err != nil {
		return keyAuthData{}, err
	}

	return td, nil
}
func (s *server) saveKeyAuthData(username string, td keyAuthData) error {
	data, err := json.Marshal(td)
	if err != nil {
		return err
	}

	return s.db.Put("keys", []byte(username), data)
}

// HANDLERS

func (s *server) keySetup(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}
	if len(req.PublicKey) == 0 {
		return api.Response{Success: false, Message: "Clave publica no proporcionada"}
	}
	kd := keyAuthData{Enabled: true, PublicKey: req.PublicKey}
	if err := s.saveKeyAuthData(req.Username, kd); err != nil {
		return api.Response{Success: false, Message: "Error al guardar la clave publica"}
	}
	return api.Response{Success: true, Message: "Autenticacion por clave activada"}
}

func (s *server) keyDisable(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}

	kd, err := s.getKeyAuthData(req.Username)
	if err != nil {
		return api.Response{Success: false, Message: "No tienes autenticacion por clave activa"}
	}
	kd.Enabled = false
	kd.PublicKey = nil
	if err := s.saveKeyAuthData(req.Username, kd); err != nil {
		return api.Response{Success: false, Message: "Error al desactivar la clave"}
	}
	return api.Response{Success: true, Message: "Autenticacion por clave desactivada"}
}

func (s *server) loginKey(req api.Request) api.Response {
	s.mu.Lock()
	pending, ok := s.pendingKey[req.TempToken]
	if ok && time.Now().After(pending.ExpiresAt) {
		delete(s.pendingKey, req.TempToken)
		ok = false
	}
	s.mu.Unlock()

	if !ok {
		return api.Response{Success: false, Message: "Token temporal invalido"}
	}

	kd, err := s.getKeyAuthData(pending.Username)
	if err != nil || !kd.Enabled {
		return api.Response{Success: false, Message: "Firma invalida"}
	}

	s.mu.Lock()
	delete(s.pendingKey, req.TempToken)
	s.mu.Unlock()

	token, err := utils.NewRandomToken(lengthToken)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear sesion"}
	}

	sess := session{
		Token:     token,
		ExpiresAt: time.Now().Add(sessionDuration),
	}

	data, err := json.Marshal(sess)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar sesion"}
	}
	if err := s.db.Put("sessions", []byte(pending.Username), data); err != nil {
		return api.Response{Success: false, Message: "Error al guardar sesion"}
	}

	return api.Response{Success: true, Message: "Login completo", Token: token, KeyAuthEnabled: true}
}
