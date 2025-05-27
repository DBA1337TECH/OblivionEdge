Oblivion Edge Secure Kernel Module - OEM Integration Guide
-----------------------------------------------------------

Thank you for licensing the Oblivion Edge Zero Trust kernel module.

Contents:
- zta_lsm.ko         -> Signed kernel module (example)
- LICENSE_OEM.md     -> License terms
- README_OEM.txt     -> This file

Integration Instructions:
1. Copy zta_lsm.ko to your target device (e.g., /lib/modules/$(uname -r)/extra/).
2. Run `depmod -a` to update module dependencies.
3. Insert the module at boot via init script or manually with `insmod`.
4. Ensure the target kernel matches the signed version.
5. For Secure Boot platforms, use the accompanying .pem signature or request a signed version.

Support:
  Email us at blake.degarza@gmail.com

-- 1337_Tech | Oblivion Edge Team
