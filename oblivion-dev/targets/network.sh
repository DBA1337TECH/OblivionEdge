#!/bin/sh
# Basic network bring-up
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
echo "[oblivion] Bringing up loopback and eth0..."

ip link set lo up
ip link set eth0 up
ip addr add 192.168.0.100/24 dev eth0
ip route add default via 192.168.0.1

echo "[oblivion] Network setup complete."

