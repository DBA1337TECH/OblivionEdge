#!/bin/bash

# Usage: ./generate_secure_user_cert.sh <username>
USERNAME=$1

if [ -z "$USERNAME" ]; then
  echo "Usage: $0 <username>"
  exit 1
fi

CERTS_DIR="./certs/users/$USERNAME"
mkdir -p "$CERTS_DIR"

# Prompt for passphrase
echo "Enter a password to protect the private key:"
read -s PASSPHRASE

# Generate encrypted private key with passphrase
openssl genrsa -aes256 -passout pass:"$PASSPHRASE" -out "$CERTS_DIR/$USERNAME.key.enc.pem" 2048

# Generate CSR
openssl req -new -key "$CERTS_DIR/$USERNAME.key.enc.pem" -passin pass:"$PASSPHRASE" \
  -subj "/CN=$USERNAME" \
  -out "$CERTS_DIR/$USERNAME.csr.pem"

# Use or create CA
CA_KEY="./certs/ca.key.pem"
CA_CERT="./certs/ca.cert.pem"
[ ! -f "$CA_KEY" ] && openssl genrsa -out "$CA_KEY" 4096
[ ! -f "$CA_CERT" ] && openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
  -subj "/CN=OblivionEdge-CA" \
  -out "$CA_CERT"

# Sign the cert
openssl x509 -req \
  -in "$CERTS_DIR/$USERNAME.csr.pem" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CERTS_DIR/$USERNAME.cert.pem" -days 365 -sha256

# Compute SHA-512 digest of encrypted cert
openssl x509 -in "$CERTS_DIR/$USERNAME.cert.pem" -noout -pubkey |
  sha512sum > "$CERTS_DIR/$USERNAME.cert.sha512"

echo "[+] Encrypted key + cert created for $USERNAME in $CERTS_DIR"

