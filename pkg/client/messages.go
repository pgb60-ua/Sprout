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
			"Leer mensaje",
			"Enviar mensaje",
			"Ver mensajes enviados",
			"Volver al menú principal",
		})

		switch choice {
		case 1:
			c.listMessages(false)
		case 2:
			c.readMessage()
		case 3:
			c.sendMessage()
		case 4:
			c.listMessages(true)
		case 5:
			return
		}
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

func (c *client) listMessages(sent bool) {
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
		return
	}
	if len(res.Messages) == 0 {
		fmt.Println("No hay mensajes.")
		return
	}
	for _, msg := range res.Messages {
		fmt.Printf("- ID: %s | De: %s | Para: %s | Fecha: %s\n", msg.ID, msg.Sender, msg.Recipient, msg.CreatedAt)
	}
}

func (c *client) readMessage() {
	ui.ClearScreen()
	fmt.Println("** Leer mensaje **")
	if len(c.messageKey) == 0 {
		fmt.Println("No hay clave privada de mensajes desbloqueada. Vuelve a iniciar sesión con la contraseña correcta.")
		return
	}

	messageID := ui.ReadInput("ID del mensaje")
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
