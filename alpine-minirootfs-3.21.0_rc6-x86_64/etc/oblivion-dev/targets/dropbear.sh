#!/bin/sh
# Dropbear SSH Daemon (using dropbearmulti, statically compiled)

echo "[oblivion] Launching Dropbear SSH..."

# Set up symlinks to dropbearmulti if they don't exist
if [ ! -x /bin/dropbear ]; then
    ln -sf /bin/dropbearmulti /usr/bin/dropbear
fi

if [ ! -x /usr/bin/dropbearkey ]; then
    ln -sf /bin/dropbearmulti /usr/bin/dropbearkey
fi

# Prepare host key directory
mkdir -p /etc/dropbear

# Generate host RSA key if missing
if [ ! -f /etc/dropbear/dropbear_rsa_host_key ]; then
    /usr/bin/dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key 2>/dev/null
    echo "[oblivion] Dropbear RSA host key generated."
fi

# Start Dropbear SSH server on port 22
/usr/bin/dropbear -F -p 22 -r /etc/dropbear/dropbear_rsa_host_key &

echo "[oblivion] Dropbear running (port 22)."

