#!/bin/sh
# Dropbear SSH Daemon (requires dropbear installed)
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
echo "[oblivion] Launching Dropbear SSH..."

mkdir -p /etc/dropbear
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key 2>/dev/null

dropbear -F -E -r /etc/dropbear/dropbear_rsa_host_key &

echo "[oblivion] Dropbear running (port 22)."
