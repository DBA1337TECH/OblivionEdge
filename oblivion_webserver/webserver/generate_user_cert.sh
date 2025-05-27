#!/bin/bash

# Usage: ./generate_user_cert.sh <username>
USERNAME=$1

if [ -z "$USERNAME" ]; then
  echo "Usage: $0 <username>"
  exit 1
fi

# Output dir
CERTS_DIR="./certs/users/$USERNAME"
mkdir -p "$CERTS_DIR"

# CA files
CA_KEY="./certs/ca.key.pem"
CA_CERT="./certs/ca.cert.pem"

# Generate CA if it doesn't exist
if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CERT" ]; then
  echo "[*] Generating CA key and certificate..."
  openssl genrsa -out "$CA_KEY" 4096
  openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
    -subj "/CN=OblivionEdge-CA" \
    -out "$CA_CERT"
fi

# Generate private key
openssl genrsa -out "$CERTS_DIR/$USERNAME.key.pem" 2048

# Generate CSR
openssl req -new -key "$CERTS_DIR/$USERNAME.key.pem" \
  -subj "/CN=$USERNAME" \
  -out "$CERTS_DIR/$USERNAME.csr.pem"

# Sign cert with CA
openssl x509 -req \
  -in "$CERTS_DIR/$USERNAME.csr.pem" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CERTS_DIR/$USERNAME.cert.pem" -days 365 -sha256

# Bundle for convenience
cat "$CERTS_DIR/$USERNAME.cert.pem" "$CERTS_DIR/$USERNAME.key.pem" > "$CERTS_DIR/$USERNAME.bundle.pem"

echo "[+] Generated TLS cert for user '$USERNAME' in: $CERTS_DIR"

