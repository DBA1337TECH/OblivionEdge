#!/bin/sh
echo "[ZTNA] Loading kernel module..."

MOD_PATH="/lib/modules/oblivion_ztna_engine.ko"

if [ -f "$MOD_PATH" ]; then
    insmod "$MOD_PATH" && echo "[ZTNA] ZTNA engine loaded successfully." || {
        echo "[ZTNA] Failed to load kernel module."
        exit 1
    }
else
    echo "[ZTNA] Module not found at $MOD_PATH"
    exit 1
fi

