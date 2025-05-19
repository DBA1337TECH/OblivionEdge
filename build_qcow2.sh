#!/bin/bash
set -e
DEV_DIR="/media/bdg/GoldenGoose/OblivionsEdge"
ROOTFS_DIR="$DEV_DIR/soho_rootfs"
QCOW2_OUT="$DEV_DIR/soho_secure_router.qcow2"
BZIMAGE_PATH="$1"

# Setup rootfs with Toybox
mkdir -p "$ROOTFS_DIR"/{bin,dev,etc,proc,sys,tmp}
cd "$ROOTFS_DIR"

# Build toybox
git clone https://github.com/landley/toybox.git
cd toybox
make defconfig && make
cp toybox ../bin/sh

# Create a minimal init script
cd ..
cat > init <<'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
echo "Welcome to the Oblivion's Edge SOHO Router Secure Linux-RT Image"
exec /bin/sh
EOF

chmod +x init
chmod +x bin/sh

# Create initramfs
find . | cpio -H newc -o | gzip > ../initramfs.gz

# Build qcow2 using QEMU tools
cd ..
dd if=/dev/zero of=rootfs.ext2 bs=1M count=64
mkfs.ext2 rootfs.ext2
mkdir mnt
sudo mount rootfs.ext2 mnt
sudo cp -r "$ROOTFS_DIR"/* mnt/
sudo umount mnt

qemu-img convert -f raw -O qcow2 rootfs.ext2 "$QCOW2_OUT"

echo "[+] qcow2 built at: $QCOW2_OUT"

