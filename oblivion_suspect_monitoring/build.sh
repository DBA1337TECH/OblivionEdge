#!/bin/bash
# // Copyright © 1337_TECH, July 2025. All rights reserved.
# // Provided "AS IS", without warranty of any kind, express or implied.
# // Use at your own risk — the authors are not liable for any damages or losses.
# // Built for research, experimentation, and security-conscious development.


set -e
echo "[*] Building Rust logger..."
cd src
cargo build --release
cd ..
echo "[+] Rust build complete: target/release/oblivion_suspect_monitoring"
