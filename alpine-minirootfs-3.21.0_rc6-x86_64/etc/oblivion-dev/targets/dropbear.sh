#!/bin/sh
# Dropbear SSH Daemon (requires dropbear installed)

echo "[oblivion] Launching Dropbear SSH..."

mkdir -p /etc/dropbear
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key 2>/dev/null

dropbear -F -E -r /etc/dropbear/dropbear_rsa_host_key &

echo "[oblivion] Dropbear running (port 22)."
