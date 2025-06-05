#!/bin/bash

set -euo pipefail

# === Prompt for input ===
read -p "👤 Enter new username: " USERNAME
read -s -p "🔑 Enter password to encrypt cert: " PASSWORD
echo

# === Setup directories ===
USER_DIR="./certs/users/$USERNAME"
mkdir -p "$USER_DIR"

KEY_FILE="$USER_DIR/temp.key.pem"
CERT_FILE="$USER_DIR/temp.cert.pem"
COMBINED_FILE="$USER_DIR/temp_combined.pem"
FINGERPRINT=""
HASH_FILE=""

# === Generate RSA private key and cert ===
openssl genrsa -out "$KEY_FILE" 2048

openssl req -new -x509 -key "$KEY_FILE" \
    -subj "/CN=$USERNAME/O=OblivionEdge" \
    -days 365 -out "$CERT_FILE"

# === Combine and encrypt with passphrase ===
cat "$KEY_FILE" "$CERT_FILE" > "$COMBINED_FILE"

ENCRYPTED_FILE="$USER_DIR/encrypted_cert.pem"
openssl pkcs8 -topk8 -inform PEM -in "$KEY_FILE" -passout pass:"$PASSWORD" \
    -out "$ENCRYPTED_FILE" -outform PEM

cat "$ENCRYPTED_FILE" "$CERT_FILE" > "$USER_DIR/full_cert.pem"

# === Compute SHA-512 digest ===
FINGERPRINT=$(openssl x509 -pubkey -noout -in "$CERT_FILE" |
    openssl pkey -pubin -outform DER |
    openssl dgst -sha512 |
    awk '{print $2}')

SHORT_ID=${FINGERPRINT:0:12}
HASH_FILE="$USER_DIR/$SHORT_ID.hash"
FINAL_CERT="$USER_DIR/$SHORT_ID.pem"

# === Save fingerprint and final cert ===
cp "$USER_DIR/full_cert.pem" "$FINAL_CERT"
echo "$FINGERPRINT" > "$HASH_FILE"

# === Cleanup ===
rm "$KEY_FILE" "$CERT_FILE" "$COMBINED_FILE" "$USER_DIR/full_cert.pem"

echo "✅ User '$USERNAME' provisioned!"
echo "📂 Certificate: $FINAL_CERT"
echo "🧾 Hash file:  $HASH_FILE"

