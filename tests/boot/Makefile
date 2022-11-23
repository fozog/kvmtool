NAME	:= init

OBJ	:= $(NAME).o
MKISOFS := $(shell which mkisofs)
ifndef MKISOFS
MKISOFS := $(shell which xorrisofs)
endif

all: $(.o)
	rm -rf rootfs
	mkdir rootfs
	gcc -static init.c -o rootfs/init
ifdef MKISOFS
	$(MKISOFS) -o boot_test.iso rootfs
else
	$(error "mkisofs or xorriso needed to build boot_test.iso")
endif

clean:
	rm -rf rootfs boot_test.iso
.PHONY: clean
