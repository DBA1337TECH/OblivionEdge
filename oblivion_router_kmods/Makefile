KERNEL_SRC := ../soho_kernel/linux

.PHONY: all clean

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD)/oblivion_router modules
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD)/oblivion_firewall modules

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD)/oblivion_router clean
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD)/oblivion_firewall clean
