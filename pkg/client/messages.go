package client

import (
	"fmt"

	"sprout/pkg/api"
	"sprout/pkg/ui"
	"sprout/pkg/utils"
)

func (c *client) messageMenu() {
	for {
		ui.ClearScreen()
		choice := ui.PrintMenu("Mensajes", []string{
			"Ver mensajes recibidos",
			"Enviar mensaje",
			"Ver mensajes enviados",
			"Volver al menú principal",
		})

		switch choice {
		case 1:
			c.inboxMenu()
		case 2:
			c.sendMessage()
		case 3:
			c.listMessages(true)
		case 4:
			return
		}
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

func (c *client) inboxMenu() {
	for {
		if !c.listMessages(false) {
			return
		}

		messageID := ui.ReadInput("ID del mensaje o 'volver'")
		if messageID == "volver" {
			return
		}
		if messageID == "" {
			continue
		}

		c.readMessageByID(messageID)
		ui.Pause("Pulsa [Enter] para volver al listado...")
	}
}

func (c *client) listMessages(sent bool) bool {
	action := api.ActionListMessages
	title := "** Mensajes recibidos **"
	if sent {
		action = api.ActionListSentMessages
		title = "** Mensajes enviados **"
	}

	ui.ClearScreen()
	fmt.Println(title)
	res := c.sendRequest(api.Request{
		Action:   action,
		Username: c.currentUser,
		Token:    c.authToken,
	})
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if !res.Success {
		c.handleSessionExpired(res)
		return false
	}
	if len(res.Messages) == 0 {
		fmt.Println("No hay mensajes.")
		return false
	}
	for _, msg := range res.Messages {
		fmt.Printf("- ID: %s | De: %s | Para: %s | Fecha: %s\n", msg.ID, msg.Sender, msg.Recipient, msg.CreatedAt)
	}
	return true
}

func (c *client) readMessage() {
	ui.ClearScreen()
	fmt.Println("** Leer mensaje **")
	if len(c.messageKey) == 0 {
		fmt.Println("No hay clave privada de mensajes desbloqueada. Vuelve a iniciar sesión con la contraseña correcta.")
		return
	}

	messageID := ui.ReadInput("ID del mensaje")
	c.readMessageByID(messageID)
}

func (c *client) readMessageByID(messageID string) {
	res := c.sendRequest(api.Request{
		Action:    api.ActionReadMessage,
		Username:  c.currentUser,
		Token:     c.authToken,
		MessageID: messageID,
	})
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if !res.Success {
		c.handleSessionExpired(res)
		return
	}

	plaintext, err := utils.DecryptMessage(res.Ciphertext, c.messageKey)
	if err != nil {
		fmt.Println("No se pudo descifrar el mensaje:", err)
		return
	}
	fmt.Println("De:", res.Sender)
	fmt.Println("Para:", res.Recipient)
	fmt.Println("Fecha:", res.CreatedAt)
	fmt.Println("--- Mensaje ---")
	fmt.Println(plaintext)
	fmt.Println("---------------")
}

func (c *client) sendMessage() {
	ui.ClearScreen()
	fmt.Println("** Enviar mensaje **")

	recipient := ui.ReadInput("Destinatario")
	keyRes := c.sendRequest(api.Request{
		Action:    api.ActionGetPublicKey,
		Username:  c.currentUser,
		Token:     c.authToken,
		Recipient: recipient,
	})
	if !keyRes.Success {
		fmt.Println("Error:", keyRes.Message)
		c.handleSessionExpired(keyRes)
		return
	}

	recipientPublicKey, err := utils.DecodeMessagePublicKey(keyRes.PublicKey)
	if err != nil {
		fmt.Println("Clave publica del destinatario invalida:", err)
		return
	}

	plaintext := ui.ReadMultiline("Introduce el mensaje")
	ciphertext, err := utils.EncryptMessage(plaintext, recipientPublicKey)
	if err != nil {
		fmt.Println("No se pudo cifrar el mensaje:", err)
		return
	}

	res := c.sendRequest(api.Request{
		Action:     api.ActionSendMessage,
		Username:   c.currentUser,
		Token:      c.authToken,
		Recipient:  recipient,
		Ciphertext: ciphertext,
	})
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		fmt.Println("ID:", res.MessageID)
	}
	c.handleSessionExpired(res)
}
