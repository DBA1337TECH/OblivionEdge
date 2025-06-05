#!/bin/sh
echo "[WEB] Starting Oblivion Edge Webserver..."

WEB_BINARY="/usr/bin/webserver"
CERT_PATH="/certs/oblivion.pem"

if [ ! -f "$WEB_BINARY" ]; then
    echo "[WEB] Webserver binary missing!"
    exit 1
fi

if [ ! -f "$CERT_PATH" ]; then
    echo "[WEB] SSL certificate not found! Generating self-signed..."
    openssl req -newkey rsa:2048 -nodes -keyout /etc/ssl/private/oblivion.key \
        -x509 -days 365 -out "$CERT_PATH" -subj "/CN=localhost"
fi

$WEB_BINARY &

