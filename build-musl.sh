#!/usr/bin/env bash

set -euo pipefail

# -------------------------------
# CONFIG
TARGET="x86_64-unknown-linux-musl"
TOOLCHAIN=$(rustup show active-toolchain | cut -d' ' -f1)
PROJECT_ROOT=$(pwd)
CARGO_CONFIG_DIR="$PROJECT_ROOT/.cargo"
CARGO_CONFIG_FILE="$CARGO_CONFIG_DIR/config.toml"
# -------------------------------

echo "[+] Detecting Rust toolchain: $TOOLCHAIN"
echo "[+] Targeting MUSL: $TARGET"

echo "[+] Installing musl-tools (requires sudo)"
sudo apt-get update
sudo apt-get install -y musl-tools

echo "[+] Adding Rust target: $TARGET"
rustup target add "$TARGET"

echo "[+] Installing MUSL stdlib for toolchain: $TOOLCHAIN"
rustup component add rust-std --target "$TARGET" --toolchain "$TOOLCHAIN"

echo "[+] Creating .cargo/config.toml with musl-gcc linker"
mkdir -p "$CARGO_CONFIG_DIR"
cat > "$CARGO_CONFIG_FILE" <<EOF
[target.$TARGET]
linker = "musl-gcc"
EOF

echo "[+] Verifying installation"
SYSROOT="$(rustc --print sysroot)"
if [ ! -d "$SYSROOT/lib/rustlib/$TARGET" ]; then
    echo "[-] ERROR: MUSL stdlib not installed properly. Check rustup or rerun this script." >&2
    exit 1
fi

echo "[+] Building project for target: $TARGET"
cargo clean
cargo build --release --target "$TARGET"

echo "[✓] Done. Binary is located at:"
echo "    target/$TARGET/release/$(basename "$PROJECT_ROOT")"

