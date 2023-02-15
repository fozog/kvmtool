ARCH         ?= $(shell $(CC) -dumpmachine | cut -f1 -d- | sed -e s,i[3456789]86,ia32, -e 's,armv7.*,arm,' )
export ARCH

ifeq ($(ARCH),aarch64)
all: inject_nisv
endif

ifeq ($(ARCH),amd64)
all: kernel pit boot
endif

kernel:
	$(MAKE) -C kernel
.PHONY: kernel

pit:
	$(MAKE) -C pit
.PHONY: pit

boot:
	$(MAKE) -C boot
.PHONY: boot

inject_nisv:
	$(MAKE) -C arm/inject_nisv
.PHONY:	inject_nisv

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C pit clean
	$(MAKE) -C boot clean
	$(MAKE) -C arm/inject_nisv clean
.PHONY: clean
