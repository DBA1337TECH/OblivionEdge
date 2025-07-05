#!/bin/bash
#
# dev.sh - Oblivion Edge Static Dev Shell 🛡️🐷
# Usage: source ./dev.sh

echo "[*] Entering Oblivion Edge Dev Environment (Static + FIPS OpenSSL)..."

# 💼 Rust setup
export CARGO_HOME="$HOME/.cargo"
export RUSTUP_HOME="$HOME/.rustup"
export PATH="$CARGO_HOME/bin:$PATH"
export RUSTUP_TOOLCHAIN=stable

# 🏗️ Compile output dir
export CARGO_TARGET_DIR="$PWD/target"

# 🔒 Static OpenSSL path (FIPS compliant)
export OPENSSL_STATIC=1
export OPENSSL_DIR="/opt/openssl-fips"
export OPENSSL_LIB_DIR="/opt/openssl-fips/lib"
export OPENSSL_INCLUDE_DIR="/opt/openssl-fips/include"
export PKG_CONFIG_ALLOW_CROSS=1
export PKG_CONFIG_PATH="$OPENSSL_LIB_DIR/pkgconfig"

# 🧱 Static linking + CPU optimizations
export CC=musl-gcc
export RUSTFLAGS="-C target-feature=+crt-static -C target-cpu=native"

# 📦 Target platform for static binaries
export CARGO_BUILD_TARGET="x86_64-unknown-linux-musl"

# 🧪 Logging and debug mode
export RUST_LOG=info
export DEV_MODE=1

# 📁 App-specific config dirs
export ZTNA_CONFIG_DIR="$PWD/config"
export ZTNA_LOG_DIR="$PWD/logs"

# 📁 Optional frontend path
export FRONTEND_DIR="$PWD/web"

# 🧪 Check if Rust + musl target is ready
if ! rustup target list | grep 'x86_64-unknown-linux-musl (installed)' > /dev/null; then
    echo "[!] MUSL target not installed. Run:"
    echo "    rustup target add x86_64-unknown-linux-musl"
fi

# ✅ Show OpenSSL version (if installed)
if [ -x "$OPENSSL_DIR/bin/openssl" ]; then
    echo "[+] OpenSSL (FIPS) version: $($OPENSSL_DIR/bin/openssl version)"
else
    echo "[!] FIPS OpenSSL not found at $OPENSSL_DIR"
fi

# 🐚 Start an interactive shell
exec bash --rcfile <(echo 'echo "Oblivion Edge Static Dev Shell 🐷 Ready!"')

