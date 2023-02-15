.section .startup
.global _entry

_entry:
	mov x0, 0xFF00
	movk x0, #0x3fff, lsl #16
	ldp x7, x8, [x0]

/* PSCI OFF */
	mov	x0, #0x8
	movk x0, #0x8400, lsl #16
	hvc #1

/* just in case to PSCI, just loop forever */
	b .
/* need to make it artificially big so that
kvmtool loader can check Linux header */
	.align(12)
	b .
