APP=inject_nisv

all: $(APP).elf

OBJS = $(patsubst %.c,%.o,$(wildcard $(SRCDIR)*.c))
OBJS += $(patsubst %.s,%.o,$(wildcard $(SRCDIR)*.s))

%.o: %.s
	@echo "AS  $@"
	@as -g -c $< -o $@

$(APP).elf: $(OBJS)
	@echo "LD  $@"
	@ld -Tbaremetal.ld $^ -o $@
	@echo "OBJCOPY  $(APP).bin"
	@objcopy -O binary $(APP).elf $(APP).bin

clean:
	@rm -f *.bin *.elf *.o
