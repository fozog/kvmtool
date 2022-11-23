TEST_TARGETS := 
ifeq ($(ARCH),x86)
TEST_TARGETS += kernel pit boot
endif

ifeq ($(ARCH),arm64)
all: inject_nisv
endif

all:  $(TEST_TARGETS)


kernel:
	$(MAKE) -C kernel
.PHONY: kernel

pit:
	$(MAKE) -C pit
	../$(PROGRAM) run pit/tick.bin
.PHONY: pit

boot:
	$(MAKE) -C boot
	../$(PROGRAM) run -d boot/boot_test.iso -p "init=init"
.PHONY: boot

inject_nisv:
	$(MAKE) -C arm/inject_nisv
	../$(PROGRAM) run --enable-nisv --kernel arm/inject_nisv/inject_nisv.bin
.PHONY: inject_nisv

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C pit clean
	$(MAKE) -C boot clean
	$(MAKE) -C arm/inject_nisv clean
.PHONY: clean
