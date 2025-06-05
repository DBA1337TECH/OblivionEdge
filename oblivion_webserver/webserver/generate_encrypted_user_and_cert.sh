#!/bin/bash

# Usage: ./gen_cert.sh <username> <passphrase>
USERNAME="$1"
PASSPHRASE="$2"
CERT_DIR="./certs/users/$USERNAME"
mkdir -p "$CERT_DIR"

# Generate private key
openssl genrsa -out "$CERT_DIR/$USERNAME.key.pem" 2048

# Generate certificate signing request (CSR)
openssl req -new -key "$CERT_DIR/$USERNAME.key.pem" \
    -subj "/CN=$USERNAME/O=OblivionEdge" \
    -out "$CERT_DIR/$USERNAME.csr.pem"

# Generate self-signed certificate
openssl x509 -req -in "$CERT_DIR/$USERNAME.csr.pem" -signkey "$CERT_DIR/$USERNAME.key.pem" \
    -days 365 -out "$CERT_DIR/$USERNAME.cert.pem"

# Encrypt the certificate
openssl enc -aes-256-cbc -salt -in "$CERT_DIR/$USERNAME.cert.pem" \
    -out "$CERT_DIR/$USERNAME.cert.enc" -pass pass:"$PASSPHRASE"

# Clean up plaintext certificate
rm "$CERT_DIR/$USERNAME.cert.pem"

echo "[+] Certificate generated and encrypted for user: $USERNAME"

