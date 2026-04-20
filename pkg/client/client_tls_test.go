package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePEMCert(t *testing.T, cert *x509.Certificate) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ca-cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("no se pudo escribir el certificado PEM: %v", err)
	}
	return path
}

func writeRandomSelfSignedCACert(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("no se pudo generar clave RSA: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Sprout Untrusted Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rawCert, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("no se pudo generar certificado de CA: %v", err)
	}

	parsed, err := x509.ParseCertificate(rawCert)
	if err != nil {
		t.Fatalf("no se pudo parsear certificado de CA: %v", err)
	}

	return writePEMCert(t, parsed)
}

func TestNewSecureHTTPClient_TrustedCA(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	caFile := writePEMCert(t, ts.Certificate())
	client, err := newSecureHTTPClient(caFile)
	if err != nil {
		t.Fatalf("newSecureHTTPClient fallo: %v", err)
	}
	client.Timeout = 2 * time.Second

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("la conexión TLS con CA de confianza debería funcionar, error: %v", err)
	}
	defer resp.Body.Close()
}

func TestNewSecureHTTPClient_UntrustedCARejected(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	caFile := writeRandomSelfSignedCACert(t)
	client, err := newSecureHTTPClient(caFile)
	if err != nil {
		t.Fatalf("newSecureHTTPClient fallo: %v", err)
	}
	client.Timeout = 2 * time.Second

	if _, err := client.Get(server.URL); err == nil {
		t.Fatalf("se esperaba rechazo TLS con una CA no confiable")
	}
}
