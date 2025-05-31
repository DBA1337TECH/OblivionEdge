#!/bin/bash
set -euo pipefail

# === Config ===
OPENSSL_VERSION="3.5.0"
OPENSSL_TARBALL="openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_URL="https://www.openssl.org/source/${OPENSSL_TARBALL}"
INSTALL_PREFIX="/opt/openssl-fips-musl-3.5"
BUILD_DIR="./openssl-fips-build"
MUSL_CC=musl-gcc

# === Prep ===
mkdir -p "$BUILD_DIR"

cd "openssl-${OPENSSL_VERSION}"

echo "[+] Removing invalid includes from mem_sec.c for musl..."
sed -i '/#.*linux\/version.h/d' crypto/mem_sec.c
sed -i '/#.*linux\/mman.h/d' crypto/mem_sec.c


# === Configure ===
echo "[+] Configuring OpenSSL with FIPS for musl..."
./Configure linux-x86_64 \
  --prefix="$INSTALL_PREFIX" \
  enable-fips \
  no-shared \
  no-dso \
  enable-acvp-tests \
  CC=$MUSL_CC \
  CFLAGS="-static -fPIC"

# === Build & Install ===
echo "[+] Building OpenSSL (static, FIPS, musl)..."
make -j"$(nproc)"
make install_sw

# === Verify ===
echo "[+] Verifying build..."
if [[ -f "$INSTALL_PREFIX/lib/ossl-modules/fips.so" ]]; then
    echo "[✔] FIPS module built successfully!"
else
    echo "[✘] FIPS module not found. Build may have failed."
    exit 1
fi

# === Final Output ===
echo -e "\n[✔] OpenSSL ${OPENSSL_VERSION} with FIPS static build complete."
echo "    Install path: $INSTALL_PREFIX"
echo "    Link with:    -L$INSTALL_PREFIX/lib -lssl -lcrypto"
echo "    Set for Rust:"
echo "      export OPENSSL_DIR=$INSTALL_PREFIX"
echo "      export OPENSSL_STATIC=1"

