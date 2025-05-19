#!/bin/bash
set -e

# Directories
WORKDIR="$HOME/soho_kernel"
KERNEL_MAIN="6.12"
KERNEL_VER="6.12.16"
RT_PATCH_VER="6.12.16-rt9"  # Example of latest compatible RT patch
JOBS=$(nproc)

# Clean setup
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# Get stable kernel
git clone --depth=1 --branch "v${KERNEL_VER}" https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
cd linux

# Get RT patch and apply
wget "https://cdn.kernel.org/pub/linux/kernel/projects/rt/${KERNEL_MAIN}/patch-${RT_PATCH_VER}.patch.xz"
xz -d "patch-${RT_PATCH_VER}.patch.xz"
patch -p1 < "patch-${RT_PATCH_VER}.patch"

# Configure for bzImage (minimal secure config)
make defconfig
make -j"$JOBS" bzImage

echo "[+] Kernel bzImage built at: $(realpath arch/x86/boot/bzImage)"

