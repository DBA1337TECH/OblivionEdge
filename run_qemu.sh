# Run with QEMU
BZIMAGE_PATH="./soho_kernel/linux/arch/x86_64/boot/bzImage"
QCOW2_OUT="./rootfs.ext2"
qemu-system-x86_64 \
  -kernel "$BZIMAGE_PATH" \
  -initrd initramfs.gz \
  -hda "$QCOW2_OUT" \
  -m 512M \
  -append "init=/oblivion-dev.target console=ttyS0"

