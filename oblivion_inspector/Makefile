# /* SPDX-License-Identifier: Proprietary */
# /*
#  * Oblivion Edge Secure Kernel Module
#  * Copyright (c) 2025, 1337_Tech, DBA: Austin, Texas
#  *
#  * This software is proprietary and confidential. Unauthorized copying,
#  * distribution, or modification of this file is strictly prohibited.
#  *
#  * Licensed for use only under the terms of a separate commercial agreement.
#  * For OEM licensing, contact: security@oblivionedge.io
#  *
#  * Redistribution or disclosure without written permission is prohibited.
#  */

obj-m += oblivion_inspector.o

KDIR := ../soho_kernel/linux
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

