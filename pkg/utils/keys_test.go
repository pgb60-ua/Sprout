package utils

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	os.RemoveAll(filepath.Join("data", "keys"))
	os.RemoveAll("data")
	os.Exit(code)
}

func TestKeyRoundTrip(t *testing.T) {
	username := "testuser"
	t.Cleanup(func() {
		os.Remove(keyPath(username))
	})

	pk, sk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("error generando par de claves: %v", err)
	}
	if len(pk) != ed25519.PublicKeySize {
		t.Fatalf("pk tiene longitud incorrecta: %d", len(pk))
	}
	if len(sk) != ed25519.PrivateKeySize {
		t.Fatalf("sk tiene longitud incorrecta: %d", len(sk))
	}

	password := "contraseña-segura"

	if err := EncryptPrivateKey(sk, password, username); err != nil {
		t.Fatalf("error cifrando clave privada: %v", err)
	}

	recovered, err := DecryptPrivateKey(password, username)
	if err != nil {
		t.Fatalf("error descifrando clave privada: %v", err)
	}

	if !recovered.Equal(sk) {
		t.Fatal("la clave recuperada no coincide con la original")
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	username := "testuser2"
	t.Cleanup(func() {
		os.Remove(keyPath(username))
	})

	_, sk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("error generando par de claves: %v", err)
	}

	if err := EncryptPrivateKey(sk, "contraseña-correcta", username); err != nil {
		t.Fatalf("error cifrando clave privada: %v", err)
	}

	_, err = DecryptPrivateKey("contraseña-incorrecta", username)
	if err == nil {
		t.Fatal("debería haber fallado con contraseña incorrecta")
	}
}

func TestDecryptCorruptFile(t *testing.T) {
	username := "testuser3"
	path := keyPath(username)
	t.Cleanup(func() {
		os.Remove(path)
	})

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("error creando directorio: %v", err)
	}
	if err := os.WriteFile(path, []byte("{json corrupto}"), 0600); err != nil {
		t.Fatalf("error escribiendo archivo corrupto: %v", err)
	}

	_, err := DecryptPrivateKey("cualquier-password", username)
	if err == nil {
		t.Fatal("debería haber fallado con archivo corrupto")
	}
}
func TestVerifySignature_Valid(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair falló: %v", err)
	}

	message := []byte("challenge-aleatorio")
	signature := ed25519.Sign(priv, message)

	if !VerifySignature(pub, message, signature) {
		t.Fatal("VerifySignature debería devolver true para una firma válida")
	}
}

func TestVerifySignature_WrongMessage(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair falló: %v", err)
	}

	signature := ed25519.Sign(priv, []byte("mensaje original"))

	if VerifySignature(pub, []byte("mensaje modificado"), signature) {
		t.Fatal("VerifySignature debería devolver false para mensaje modificado")
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair falló: %v", err)
	}
	otherPub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (2) falló: %v", err)
	}

	message := []byte("challenge-aleatorio")
	signature := ed25519.Sign(priv, message)

	if VerifySignature(otherPub, message, signature) {
		t.Fatal("VerifySignature debería devolver false para clave pública incorrecta")
	}
}

func TestVerifySignature_TamperedSignature(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair falló: %v", err)
	}

	message := []byte("challenge-aleatorio")
	signature := ed25519.Sign(priv, message)
	signature[0] ^= 0xff

	if VerifySignature(pub, message, signature) {
		t.Fatal("VerifySignature debería devolver false para firma manipulada")
	}
}
