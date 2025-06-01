# Run with QEMU
BZIMAGE_PATH="./soho_kernel/linux/arch/x86_64/boot/bzImage"
QCOW2_OUT="./rootfs.ext2"
qemu-system-x86_64 \
  -kernel "$BZIMAGE_PATH" \
  -initrd initramfs.gz \
  -hda "$QCOW2_OUT" \
  -m 512M \
  -append "init=/oblivion-dev.target console=ttyS0 ip=192.168.0.100::192.168.0.1:255.255.255.0::eth0:off" \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device e1000,netdev=net0 

