obj-m := kfetch_mod_312512023.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

load:
	sudo insmod kfetch_mod_312512023.ko
	@if [ ! -e /dev/kfetch ]; then \
		sudo mknod /dev/kfetch c $$(awk '$$2 == "kfetch" {print $$1}' /proc/devices) 0; \
		sudo chmod 666 /dev/kfetch; \
	fi

unload:
	sudo rmmod kfetch_mod_312512023
	@if [ -e /dev/kfetch ]; then \
		sudo rm /dev/kfetch; \
	fi

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf *.o *.mod.c *.order *.symvers .*.cmd .tmp_versions
