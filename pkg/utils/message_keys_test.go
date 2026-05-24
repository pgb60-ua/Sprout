package utils

import (
	"os"
	"testing"
)

func TestMessageEncryptDecrypt(t *testing.T) {
	publicKey, privateKey, err := GenerateMessageKeyPair()
	if err != nil {
		t.Fatalf("error generando claves: %v", err)
	}

	encodedPublicKey, err := EncodeMessagePublicKey(publicKey)
	if err != nil {
		t.Fatalf("error codificando clave publica: %v", err)
	}
	decodedPublicKey, err := DecodeMessagePublicKey(encodedPublicKey)
	if err != nil {
		t.Fatalf("error decodificando clave publica: %v", err)
	}

	ciphertext, err := EncryptMessage("mensaje secreto", decodedPublicKey)
	if err != nil {
		t.Fatalf("error cifrando mensaje: %v", err)
	}
	plaintext, err := DecryptMessage(ciphertext, privateKey)
	if err != nil {
		t.Fatalf("error descifrando mensaje: %v", err)
	}
	if plaintext != "mensaje secreto" {
		t.Fatalf("plaintext inesperado: %q", plaintext)
	}
}

func TestMessageDecryptWrongPrivateKey(t *testing.T) {
	publicKey, _, err := GenerateMessageKeyPair()
	if err != nil {
		t.Fatalf("error generando claves de destinatario: %v", err)
	}
	_, wrongPrivateKey, err := GenerateMessageKeyPair()
	if err != nil {
		t.Fatalf("error generando claves incorrectas: %v", err)
	}

	ciphertext, err := EncryptMessage("mensaje secreto", publicKey)
	if err != nil {
		t.Fatalf("error cifrando mensaje: %v", err)
	}
	if _, err := DecryptMessage(ciphertext, wrongPrivateKey); err == nil {
		t.Fatal("deberia fallar con clave privada incorrecta")
	}
}

func TestMessagePrivateKeyRoundTrip(t *testing.T) {
	username := "mensajes-test"
	t.Cleanup(func() {
		_ = os.Remove(messageKeyPath(username))
	})

	_, privateKey, err := GenerateMessageKeyPair()
	if err != nil {
		t.Fatalf("error generando claves: %v", err)
	}
	if err := EncryptMessagePrivateKey(privateKey, "password123", username); err != nil {
		t.Fatalf("error cifrando clave privada: %v", err)
	}
	recovered, err := DecryptMessagePrivateKey("password123", username)
	if err != nil {
		t.Fatalf("error descifrando clave privada: %v", err)
	}
	if string(recovered) != string(privateKey) {
		t.Fatal("la clave recuperada no coincide")
	}
	if _, err := DecryptMessagePrivateKey("otra-password", username); err == nil {
		t.Fatal("deberia fallar con password incorrecta")
	}
}
