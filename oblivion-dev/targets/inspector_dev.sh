#!/bin/sh
# Load Oblivion Edge Packet Inspector kernel module
# /* SPDX-License-Identifier: Proprietary */
# /*
#  * Oblivion Edge Secure Kernel Module
#  * Copyright (c) 2025, 1337_Tech, DBA: Austin, Texas
#  *
#  * This software is proprietary and confidential. Unauthorized copying,
#  * distribution, or modification of this file is strictly prohibited.
#  *
#  * Licensed for use only under the terms of a separate commercial agreement.
#  * For OEM licensing, contact: security@oblivionedge.io
#  *
#  * Redistribution or disclosure without written permission is prohibited.
#  */
echo "[oblivion] Loading packet inspector module..."

if insmod /lib/modules/oblivion_inspector.ko 2>/dev/null; then
    echo "[oblivion] Inspector module loaded."
else
    echo "[!] Failed to load inspector module."
fi

