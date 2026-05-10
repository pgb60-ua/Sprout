package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/store"
	"sprout/pkg/utils"
)

const (
	publicKeysNamespace          = "public_keys"
	messagesNamespace            = "messages"
	messagesByRecipientNamespace = "messages_by_recipient"
	messagesBySenderNamespace    = "messages_by_sender"
	messageIndexSeparator        = "\x00"
)

type storedMessage struct {
	ID         string `json:"id"`
	Sender     string `json:"sender"`
	Recipient  string `json:"recipient"`
	CreatedAt  string `json:"created_at"`
	Ciphertext string `json:"ciphertext"`
}

func (s *server) getPublicKey(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" || req.Recipient == "" {
		return api.Response{Success: false, Message: "Faltan datos"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}
	if err := utils.ValidateUsername(req.Recipient); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}

	publicKey, err := s.db.Get(publicKeysNamespace, []byte(req.Recipient))
	if err != nil {
		return api.Response{Success: false, Message: "El destinatario no tiene clave publica de mensajes"}
	}

	return api.Response{Success: true, Message: "Clave publica encontrada", PublicKey: string(publicKey)}
}

func (s *server) sendMessage(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" || req.Recipient == "" || req.Ciphertext == "" {
		return api.Response{Success: false, Message: "Faltan datos del mensaje"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}
	if err := utils.ValidateUsername(req.Recipient); err != nil {
		return api.Response{Success: false, Message: err.Error()}
	}
	exists, err := s.userExists(req.Recipient)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar destinatario"}
	}
	if !exists {
		return api.Response{Success: false, Message: "El destinatario no existe"}
	}
	if _, err := s.db.Get(publicKeysNamespace, []byte(req.Recipient)); err != nil {
		return api.Response{Success: false, Message: "El destinatario no tiene clave publica de mensajes"}
	}
	if _, err := base64.RawStdEncoding.DecodeString(req.Ciphertext); err != nil {
		return api.Response{Success: false, Message: "Mensaje cifrado invalido"}
	}

	id, err := utils.NewRandomToken(16)
	if err != nil {
		return api.Response{Success: false, Message: "Error al generar identificador del mensaje"}
	}
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	msg := storedMessage{
		ID:         id,
		Sender:     req.Username,
		Recipient:  req.Recipient,
		CreatedAt:  createdAt,
		Ciphertext: req.Ciphertext,
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return api.Response{Success: false, Message: "Error al serializar mensaje"}
	}

	if err := s.db.Put(messagesNamespace, []byte(id), msgBytes); err != nil {
		return api.Response{Success: false, Message: "Error al guardar mensaje"}
	}
	if err := s.db.Put(messagesByRecipientNamespace, []byte(messageIndexKey(req.Recipient, createdAt, id)), []byte(id)); err != nil {
		return api.Response{Success: false, Message: "Error al indexar mensaje recibido"}
	}
	if err := s.db.Put(messagesBySenderNamespace, []byte(messageIndexKey(req.Username, createdAt, id)), []byte(id)); err != nil {
		return api.Response{Success: false, Message: "Error al indexar mensaje enviado"}
	}

	return api.Response{Success: true, Message: "Mensaje enviado", MessageID: id}
}

func (s *server) listMessages(req api.Request) api.Response {
	return s.listIndexedMessages(req, messagesByRecipientNamespace, true)
}

func (s *server) listSentMessages(req api.Request) api.Response {
	return s.listIndexedMessages(req, messagesBySenderNamespace, false)
}

func (s *server) listIndexedMessages(req api.Request, namespace string, inbox bool) api.Response {
	if req.Username == "" || req.Token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}

	keys, err := s.db.KeysByPrefix(namespace, []byte(req.Username+messageIndexSeparator))
	if err != nil {
		if errors.Is(err, store.ErrNamespaceNotFound) {
			return api.Response{Success: true, Message: "No hay mensajes", Messages: []api.MessageSummary{}}
		}
		return api.Response{Success: false, Message: "Error al listar mensajes"}
	}

	messages := make([]api.MessageSummary, 0, len(keys))
	for _, key := range keys {
		messageID, err := s.db.Get(namespace, key)
		if err != nil {
			continue
		}
		msg, err := s.loadMessage(string(messageID))
		if err != nil {
			continue
		}
		if inbox && msg.Recipient != req.Username {
			continue
		}
		if !inbox && msg.Sender != req.Username {
			continue
		}
		messages = append(messages, api.MessageSummary{
			ID:        msg.ID,
			Sender:    msg.Sender,
			Recipient: msg.Recipient,
			CreatedAt: msg.CreatedAt,
		})
	}

	return api.Response{Success: true, Message: "Listado correcto", Messages: messages}
}

func (s *server) readMessage(req api.Request) api.Response {
	if req.Username == "" || req.Token == "" || req.MessageID == "" {
		return api.Response{Success: false, Message: "Faltan datos"}
	}
	if !s.isTokenValid(req.Username, req.Token) {
		return api.Response{Success: false, Message: "Token invalido o sesion expirada", SessionExpired: true}
	}
	if strings.Contains(req.MessageID, "/") || strings.Contains(req.MessageID, messageIndexSeparator) {
		return api.Response{Success: false, Message: "Identificador de mensaje invalido"}
	}

	msg, err := s.loadMessage(req.MessageID)
	if err != nil {
		return api.Response{Success: false, Message: "Mensaje no encontrado"}
	}
	if msg.Recipient != req.Username {
		return api.Response{Success: false, Message: "No tienes acceso a este mensaje"}
	}

	return api.Response{
		Success:    true,
		Message:    "Mensaje recuperado",
		MessageID:  msg.ID,
		Sender:     msg.Sender,
		Recipient:  msg.Recipient,
		CreatedAt:  msg.CreatedAt,
		Ciphertext: msg.Ciphertext,
	}
}

func (s *server) loadMessage(id string) (storedMessage, error) {
	var msg storedMessage
	raw, err := s.db.Get(messagesNamespace, []byte(id))
	if err != nil {
		return msg, err
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return msg, fmt.Errorf("mensaje corrupto: %w", err)
	}
	return msg, nil
}

func messageIndexKey(username, createdAt, id string) string {
	return username + messageIndexSeparator + createdAt + messageIndexSeparator + id
}
