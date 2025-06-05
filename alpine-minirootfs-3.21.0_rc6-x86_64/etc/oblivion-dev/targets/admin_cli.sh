#!/bin/sh
echo "[CLI] Launching Oblivion Admin CLI..."

CLI_BIN="/usr/bin/oblivion-admin-cli"
KEY="/etc/oblivion/ztna_secret.key"

if [ ! -f "$CLI_BIN" ]; then
    echo "[CLI] Admin CLI binary missing!"
    exit 1
fi

if [ ! -f "$KEY" ]; then
    echo "[CLI] Auth key missing. Generating placeholder key..."
    echo -ne "\xef\xbe\xad\xde" > "$KEY"
fi

$CLI_BIN status &

