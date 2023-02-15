ENTRY(_entry)
SECTIONS
{
	.text : {
	       	*(.startup)
	       	*(.text)
	}
	.data : {
		. = ALIGN(8);
		*(.rodata);
		. = ALIGN(8);
	       	*(.data);
		. = ALIGN(8);
		*(.got);
		. = ALIGN(8);
		*(.got.plt);
		. = ALIGN(8);
		*(.data.rel.local);
	}
	.bss : { *(.bss COMMON) }
	. = ALIGN(65536);
	PROVIDE_HIDDEN(__stack_top = .);
}
