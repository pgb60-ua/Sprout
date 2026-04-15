package server

import (
	"encoding/json"
	"sprout/pkg/api"
	"sprout/pkg/utils"
	"time"
)

type totpData struct {
	Enabled       bool   `json:"enabled"`
	Secret        string `json:"secret"`
	PendingSecret string `json:"pending_secret"`
}

type pendingTOTPLogin struct {
	Username  string
	ExpiresAt time.Time
}

func (s *server) getTOTPData(username string) (totpData, error) {
	data, err := s.db.Get("totp", []byte(username))
	if err != nil {
		return totpData{}, err
	}

	var td totpData
	if err := json.Unmarshal(data, &td); err != nil {
		return totpData{}, err
	}

	return td, nil
}
func (s *server) saveTOTPData(username string, td totpData) error {
	data, err := json.Marshal(td)
	if err != nil {
		return err
	}

	return s.db.Put("totp", []byte(username), data)
}

// HANDLERS

func (s *server) tOTPSetup(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}

	// Creo datos vacios si no existen
	td, err := s.getTOTPData(req.Username)
	if err != nil {
		td = totpData{}
	}
	var secret string
	if (td.PendingSecret == "" && !td.Enabled) || req.ForceNewSecret {
		secret, err = utils.GenerateTOTPSecret()
		if err != nil {
			return api.Response{Success: false, Message: "Error al generar el secreto TOTP"}
		}
		td.PendingSecret = secret
		if err := s.saveTOTPData(req.Username, td); err != nil {
			return api.Response{Success: false, Message: "Error al guardar secreto TOTP"}
		}
	} else {
		secret = td.PendingSecret
	}

	return api.Response{
		Success:    true,
		Message:    "Secreto TOTP generado. Confirma con un código antes de activarlo",
		OTPAuthURI: utils.BuildOTPAuthURI(secret, req.Username, "Sprout"),
	}
}

func (s *server) tOTPConfirm(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}

	td, err := s.getTOTPData(req.Username)
	if err != nil || td.PendingSecret == "" {
		return api.Response{Success: false, Message: "No hay un secreto TOTP pendiente"}
	}

	// Verifico cofigo con el secreto pendiente
	if !utils.VerifyTOTPCode(td.PendingSecret, req.TOTPCode, time.Now()) {
		return api.Response{Success: false, Message: "Codigo TOTP incorrecto"}
	}

	// Activo el TOTP
	td.Secret = td.PendingSecret
	td.PendingSecret = ""
	td.Enabled = true
	if err := s.saveTOTPData(req.Username, td); err != nil {
		return api.Response{Success: false, Message: "Error al activar TOTP"}
	}

	return api.Response{Success: true, Message: "TOTP activado correctamente"}
}

func (s *server) loginTOTP(req api.Request) api.Response {
	s.mu.Lock()
	pending, ok := s.pendingTOTP[req.TempToken]
	if ok && time.Now().After(pending.ExpiresAt) {
		delete(s.pendingTOTP, req.TempToken)
		ok = false
	}
	s.mu.Unlock()

	if !ok {
		return api.Response{Success: false, Message: "Token temporal invalido"}
	}

	td, err := s.getTOTPData(pending.Username)
	if err != nil || !td.Enabled {
		return api.Response{Success: false, Message: "El usuario no tiene TOTP activo"}
	}

	if !utils.VerifyTOTPCode(td.Secret, req.TOTPCode, time.Now()) {
		s.mu.Lock()
		delete(s.pendingTOTP, req.TempToken)
		s.mu.Unlock()
		return api.Response{Success: false, Message: "Codigo TOTP incorrecto"}
	}

	s.mu.Lock()
	delete(s.pendingTOTP, req.TempToken)
	s.mu.Unlock()

	token, err := utils.NewRandomToken(lengthToken)
	if err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	sess := session{
		Token:     token,
		ExpiresAt: time.Now().Add(sessionDuration),
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar sesión"}
	}
	if err := s.db.Put("sessions", []byte(pending.Username), data); err != nil {
		return api.Response{Success: false, Message: "Error al guardar sesión"}
	}

	return api.Response{Success: true, Message: "Login completo", Token: token, TOTPEnabled: true}
}

func (s *server) totpDisable(req api.Request) api.Response {
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}

	td, err := s.getTOTPData(req.Username)
	if err != nil || !td.Enabled {
		return api.Response{Success: false, Message: "No tienes TOTP activo"}
	}

	// Pido el codigo actual para confirmar que es el usuario
	if !utils.VerifyTOTPCode(td.Secret, req.TOTPCode, time.Now()) {
		return api.Response{Success: false, Message: "Codigo TOTP incorrecto"}
	}

	td.Enabled = false
	td.Secret = ""
	td.PendingSecret = ""
	if err := s.saveTOTPData(req.Username, td); err != nil {
		return api.Response{Success: false, Message: "Error al desactivar TOTP"}
	}

	return api.Response{Success: true, Message: "TOTP desactivado correctamente"}
}
