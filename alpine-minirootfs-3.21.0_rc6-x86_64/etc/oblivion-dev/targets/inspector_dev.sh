#!/bin/sh
# Load Oblivion Edge Packet Inspector kernel module

echo "[oblivion] Loading packet inspector module..."

if insmod /lib/modules/oblivion_inspector.ko 2>/dev/null; then
    echo "[oblivion] Inspector module loaded."
else
    echo "[!] Failed to load inspector module."
fi

