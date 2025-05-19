#!/bin/sh
# Basic network bring-up

echo "[oblivion] Bringing up loopback and eth0..."

ip link set lo up
ip link set eth0 up
ip addr add 192.168.0.100/24 dev eth0
ip route add default via 192.168.0.1

echo "[oblivion] Network setup complete."

