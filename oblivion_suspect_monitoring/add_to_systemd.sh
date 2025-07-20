#!/bin/bash
# // Copyright © 1337_TECH, July 2025. All rights reserved.
# // Provided "AS IS", without warranty of any kind, express or implied.
# // Use at your own risk — the authors are not liable for any damages or losses.
# // Built for research, experimentation, and security-conscious development.



set -e

SERVICE_NAME=oblivion_suspect_logger
BIN_PATH=$(realpath target/release/oblivion_suspect_monitoring)

echo "[*] Creating systemd service for $SERVICE_NAME..."

SERVICE_FILE=/etc/systemd/system/$SERVICE_NAME.service

sudo bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=Oblivion Suspect Monitoring Logger
After=network.target

[Service]
ExecStart=$BIN_PATH
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Reloading systemd daemon..."
sudo systemctl daemon-reexec
sudo systemctl daemon-reload

echo "[*] Enabling and starting $SERVICE_NAME..."
sudo systemctl enable $SERVICE_NAME
sudo systemctl start $SERVICE_NAME

echo "[+] $SERVICE_NAME successfully installed and running."
