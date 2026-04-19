#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="${1:-data/certs}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl no está instalado." >&2
  exit 1
fi

mkdir -p "$CERT_DIR"

CA_KEY="$CERT_DIR/ca-key.pem"
CA_CERT="$CERT_DIR/ca-cert.pem"
SERVER_KEY="$CERT_DIR/server-key.pem"
SERVER_CSR="$CERT_DIR/server.csr"
SERVER_CERT="$CERT_DIR/server-cert.pem"
SERVER_EXT="$CERT_DIR/server-ext.cnf"

openssl genrsa -out "$CA_KEY" 4096
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 825 -out "$CA_CERT" -subj "/CN=Sprout Dev CA"

openssl genrsa -out "$SERVER_KEY" 2048
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -subj "/CN=localhost"

cat > "$SERVER_EXT" <<'EXT'
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
basicConstraints=CA:FALSE
EXT

openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVER_CERT" -days 825 -sha256 -extfile "$SERVER_EXT"

rm -f "$SERVER_CSR" "$SERVER_EXT" "$CERT_DIR/ca-cert.srl"
chmod 600 "$CA_KEY" "$SERVER_KEY"

echo "Certificados generados en $CERT_DIR"
echo " - CA: $CA_CERT"
echo " - Cert servidor: $SERVER_CERT"
echo " - Clave servidor: $SERVER_KEY"
