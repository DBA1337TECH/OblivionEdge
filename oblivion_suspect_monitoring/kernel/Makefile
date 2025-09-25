# Makefile for building suspect kernel modules
# Copyright © 1337_TECH, July 2025.

# Kernel source/build directory (override on command line if needed)
KDIR ?= ../../soho_kernel/linux
PWD  := $(shell pwd)

# List of modules
MODULES := read_suspect_packets read_suspect_udp_packets

# obj-m needs .o entries for each module
obj-m := $(addsuffix .o,$(MODULES))

# Default target
all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Install modules into kernel's modules directory (may need sudo)
modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

# Clean build artifacts
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f *.mod.c Module.symvers modules.order .*.cmd .tmp_versions

# Convenience: build a specific module
# Usage: make build MODULE=read_suspect_udp_packets
build:
ifdef MODULE
	$(MAKE) -C $(KDIR) M=$(PWD) $(MODULE).o
else
	@echo "Usage: make build MODULE=<module_name>"
	@false
endif

.PHONY: all modules modules_install clean build
