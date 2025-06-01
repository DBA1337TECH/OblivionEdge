#!/bin/bash
set -e

UBOOT_DIR="$HOME/uboot_secure"

# Clone U-Boot mainline and checkout stable branch
git clone https://source.denx.de/u-boot/u-boot.git "$UBOOT_DIR"
cd "$UBOOT_DIR"
git checkout v2025.07-rc2   # Replace with latest stable version

# Setup environment
make defconfig

echo "[+] U-Boot is cloned and ready in $UBOOT_DIR"
echo "[*] Next steps: customize board support and secure boot sequences"

