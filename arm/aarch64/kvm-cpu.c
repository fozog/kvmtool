#include "kvm/kvm-cpu.h"
#include "kvm/kvm.h"
#include "kvm/virtio.h"
#include "kvm/symbol.h"

#include <asm/ptrace.h>
#include <linux/err.h>


#ifdef CONFIG_HAS_OPCODES

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <dis-asm.h>

disassembler_ftype disasm;

#ifdef CONFIG_HAS_BFD
// from symbol.c
extern asymbol **syms;
extern asection *section;
extern int nr_syms;
extern bfd *abfd;

#define ABFD	abfd

#else

#define ABFD	NULL
#endif

typedef struct {
  char *insn_buffer;
  bool reenter;
} stream_state;

/* This approach isn't very memory efficient or clear,
 * but it avoids external size/buffer tracking in this
 * example.
 */
static int dis_sprintf(void *stream, const char *fmt, ...) {
	stream_state *ss = (stream_state *)stream;

	va_list arg;
	va_start(arg, fmt);
	if (!ss->reenter) {
		int r=vasprintf(&ss->insn_buffer, fmt, arg);
		if (r < 0) die("disassembler memory error");
		ss->reenter = true;
	} else {
		char *tmp;
		int r = vasprintf(&tmp, fmt, arg);
		if (r < 0) die("disassembler memory error");
		char *tmp2;
		r = asprintf(&tmp2, "%s%s", ss->insn_buffer, tmp);
		if (r < 0) die("disassembler memory error");
		free(ss->insn_buffer);
		free(tmp);
		ss->insn_buffer = tmp2;
	}
	va_end(arg);

	return 0;
}


static char* disassemble(uint8_t *input_buffer, size_t input_buffer_size) {
	char *disassembled = NULL;
	stream_state ss = {};

	disassemble_info disasm_info = {};
	init_disassemble_info(&disasm_info, &ss, dis_sprintf);
	disasm_info.arch = bfd_arch_aarch64;
	disasm_info.mach = bfd_mach_aarch64;
	disasm_info.read_memory_func = buffer_read_memory;
	disasm_info.buffer = input_buffer;
	disasm_info.buffer_vma = 0;
	disasm_info.buffer_length = input_buffer_size;
#ifdef CONFIG_HAS_BFD
	disasm_info.section = section;
	disasm_info.symbols = syms;
	disasm_info.num_symbols = nr_syms;
#endif
	disassemble_init_for_target(&disasm_info);

	size_t pc = 0;
	while (pc < input_buffer_size) {
		size_t insn_size = disasm(pc, &disasm_info);
		pc += insn_size;

		if (disassembled == NULL) {
			int r = asprintf(&disassembled, "%s", ss.insn_buffer);
			if (r < 0) die("disassembler memory error");
		} else {
			char *tmp;
			int r = asprintf(&tmp, "%s\n%s", disassembled, ss.insn_buffer);
			if (r < 0) die("disassembler memory error");
			free(disassembled);
			disassembled = tmp;
		}

		/* Reset the stream state after each instruction decode.
		*/
		free(ss.insn_buffer);
		ss.reenter = false;
	}

	return disassembled;
}

int disas_init(struct kvm *kvm);
int disas_init(struct kvm *kvm)
{
	disasm = disassembler(bfd_arch_aarch64, false, bfd_mach_aarch64, ABFD);
	return 0;
}
late_init(disas_init)

int disas_exit(struct kvm *kvm);
int disas_exit(struct kvm *kvm)
{
	// anything to do?
	return 0;
}
late_init(disas_exit)

#endif


#define COMPAT_PSR_F_BIT	0x00000040
#define COMPAT_PSR_I_BIT	0x00000080
#define COMPAT_PSR_E_BIT	0x00000200
#define COMPAT_PSR_MODE_SVC	0x00000013

#define SCTLR_EL1_E0E_MASK	(1 << 24)
#define SCTLR_EL1_EE_MASK	(1 << 25)

static __u64 __core_reg_id(__u64 offset)
{
	__u64 id = KVM_REG_ARM64 | KVM_REG_ARM_CORE | offset;

	if (offset < KVM_REG_ARM_CORE_REG(fp_regs))
		id |= KVM_REG_SIZE_U64;
	else if (offset < KVM_REG_ARM_CORE_REG(fp_regs.fpsr))
		id |= KVM_REG_SIZE_U128;
	else
		id |= KVM_REG_SIZE_U32;

	return id;
}

#define ARM64_CORE_REG(x) __core_reg_id(KVM_REG_ARM_CORE_REG(x))

unsigned long kvm_cpu__get_vcpu_mpidr(struct kvm_cpu *vcpu)
{
	struct kvm_one_reg reg;
	u64 mpidr;

	reg.id = ARM64_SYS_REG(ARM_CPU_ID, ARM_CPU_ID_MPIDR);
	reg.addr = (u64)&mpidr;
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (get_mpidr vcpu%ld", vcpu->cpu_id);

	return mpidr;
}

static void reset_vcpu_aarch32(struct kvm_cpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_one_reg reg;
	u64 data;

	reg.addr = (u64)&data;

	/* pstate = all interrupts masked */
	data	= COMPAT_PSR_I_BIT | COMPAT_PSR_F_BIT | COMPAT_PSR_MODE_SVC;
	reg.id	= ARM64_CORE_REG(regs.pstate);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (spsr[EL1])");

	/* Secondary cores are stopped awaiting PSCI wakeup */
	if (vcpu->cpu_id != 0)
		return;

	/* r0 = 0 */
	data	= 0;
	reg.id	= ARM64_CORE_REG(regs.regs[0]);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (r0)");

	/* r1 = machine type (-1) */
	data	= -1;
	reg.id	= ARM64_CORE_REG(regs.regs[1]);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (r1)");

	/* r2 = physical address of the device tree blob */
	data	= kvm->arch.dtb_guest_start;
	reg.id	= ARM64_CORE_REG(regs.regs[2]);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (r2)");

	/* pc = start of kernel image */
	data	= kvm->arch.kern_guest_start;
	reg.id	= ARM64_CORE_REG(regs.pc);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (pc)");
}

static void reset_vcpu_aarch64(struct kvm_cpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_one_reg reg;
	u64 data;

	reg.addr = (u64)&data;

	/* pstate = all interrupts masked */
	data	= PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h;
	reg.id	= ARM64_CORE_REG(regs.pstate);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (spsr[EL1])");

	/* x1...x3 = 0 */
	data	= 0;
	reg.id	= ARM64_CORE_REG(regs.regs[1]);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (x1)");

	reg.id	= ARM64_CORE_REG(regs.regs[2]);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (x2)");

	reg.id	= ARM64_CORE_REG(regs.regs[3]);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (x3)");

	//make sure we know what VBAR is.
	//This will be needed to handle TFA execution later
	data	= 0xf0000000;
	reg.id	= KVM_REG_ARM_VBAR_EL1;
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (VBAR_EL1)");

	/* Secondary cores are stopped awaiting PSCI wakeup */
	if (vcpu->cpu_id == 0) {
		/* x0 = physical address of the device tree blob */
		data	= kvm->arch.dtb_guest_start;
		reg.id	= ARM64_CORE_REG(regs.regs[0]);
		if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
			die_perror("KVM_SET_ONE_REG failed (x0)");

		/* pc = start of kernel image */
		data	= kvm->arch.kern_guest_start;
		reg.id	= ARM64_CORE_REG(regs.pc);
		if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
			die_perror("KVM_SET_ONE_REG failed (pc)");
	}
}

void kvm_cpu__select_features(struct kvm *kvm, struct kvm_vcpu_init *init)
{
	if (kvm->cfg.arch.aarch32_guest) {
		if (!kvm__supports_extension(kvm, KVM_CAP_ARM_EL1_32BIT))
			die("32bit guests are not supported\n");
		init->features[0] |= 1UL << KVM_ARM_VCPU_EL1_32BIT;
	}

	if (kvm->cfg.arch.has_pmuv3) {
		if (!kvm__supports_extension(kvm, KVM_CAP_ARM_PMU_V3))
			die("PMUv3 is not supported");
		init->features[0] |= 1UL << KVM_ARM_VCPU_PMU_V3;
	}

	/* Enable pointer authentication if available */
	if (kvm__supports_extension(kvm, KVM_CAP_ARM_PTRAUTH_ADDRESS) &&
	    kvm__supports_extension(kvm, KVM_CAP_ARM_PTRAUTH_GENERIC)) {
		init->features[0] |= 1UL << KVM_ARM_VCPU_PTRAUTH_ADDRESS;
		init->features[0] |= 1UL << KVM_ARM_VCPU_PTRAUTH_GENERIC;
	}

	/* Enable SVE if available */
	if (kvm__supports_extension(kvm, KVM_CAP_ARM_SVE))
		init->features[0] |= 1UL << KVM_ARM_VCPU_SVE;
}

int kvm_cpu__configure_features(struct kvm_cpu *vcpu)
{
	if (kvm__supports_extension(vcpu->kvm, KVM_CAP_ARM_SVE)) {
		int feature = KVM_ARM_VCPU_SVE;

		if (ioctl(vcpu->vcpu_fd, KVM_ARM_VCPU_FINALIZE, &feature)) {
			pr_err("KVM_ARM_VCPU_FINALIZE: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}

void kvm_cpu__reset_vcpu(struct kvm_cpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	cpu_set_t *affinity;
	int ret;

	affinity = kvm->arch.vcpu_affinity_cpuset;
	if (affinity) {
		ret = sched_setaffinity(0, sizeof(cpu_set_t), affinity);
		if (ret == -1)
			die_perror("sched_setaffinity");
	}

	if (kvm->cfg.arch.aarch32_guest)
		return reset_vcpu_aarch32(vcpu);
	else
		return reset_vcpu_aarch64(vcpu);
}

int kvm_cpu__get_endianness(struct kvm_cpu *vcpu)
{
	struct kvm_one_reg reg;
	u64 psr;
	u64 sctlr;

	/*
	 * Quoting the definition given by Peter Maydell:
	 *
	 * "Endianness of the CPU which does the virtio reset at the
	 * point when it does that reset"
	 *
	 * We first check for an AArch32 guest: its endianness can
	 * change when using SETEND, which affects the CPSR.E bit.
	 *
	 * If we're AArch64, use SCTLR_EL1.E0E if access comes from
	 * EL0, and SCTLR_EL1.EE if access comes from EL1.
	 */
	reg.id = ARM64_CORE_REG(regs.pstate);
	reg.addr = (u64)&psr;
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (spsr[EL1])");

	if (psr & PSR_MODE32_BIT)
		return (psr & COMPAT_PSR_E_BIT) ? VIRTIO_ENDIAN_BE : VIRTIO_ENDIAN_LE;

	reg.id = ARM64_SYS_REG(ARM_CPU_CTRL, ARM_CPU_CTRL_SCTLR_EL1);
	reg.addr = (u64)&sctlr;
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (SCTLR_EL1)");

	if ((psr & PSR_MODE_MASK) == PSR_MODE_EL0t)
		sctlr &= SCTLR_EL1_E0E_MASK;
	else
		sctlr &= SCTLR_EL1_EE_MASK;
	return sctlr ? VIRTIO_ENDIAN_BE : VIRTIO_ENDIAN_LE;
}

#define MAX_SYM_LEN 128

void kvm_cpu__show_code(struct kvm_cpu *vcpu)
{
	struct kvm_one_reg reg;
	unsigned long data;
	int debug_fd = kvm_cpu__get_debug_fd();
	char sym[MAX_SYM_LEN] = SYMBOL_DEFAULT_UNKNOWN, *psym;
	
	reg.addr = (u64)&data;

	
	dprintf(debug_fd, "\nPC: ");
	reg.id = ARM64_CORE_REG(regs.pc);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (show_code @ PC)");

	kvm__dump_mem(vcpu->kvm, data, 32, debug_fd);

	psym = symbol_lookup(vcpu->kvm, data, sym, MAX_SYM_LEN);
	if (IS_ERR(psym))
		dprintf(debug_fd,
			"Warning: symbol_lookup() failed to find symbol "
			"with error: %ld\n", PTR_ERR(psym));

	dprintf(debug_fd, " (%s) \n", sym);
	dprintf(debug_fd, "\n*lr:\n");
	reg.id = ARM64_CORE_REG(regs.regs[30]);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (show_code @ LR)");

	kvm__dump_mem(vcpu->kvm, data, 32, debug_fd);
}

void kvm_cpu__show_step(struct kvm_cpu *vcpu)
{
	struct kvm_one_reg reg;
	unsigned long pc;
	int debug_fd = kvm_cpu__get_debug_fd();
	
	char sym[MAX_SYM_LEN]  = SYMBOL_DEFAULT_UNKNOWN;
	char* psym = NULL;
	char* opcode = NULL;
	
	reg.id		= ARM64_CORE_REG(regs.pc);
	reg.addr = (u64)&pc;
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (pc)");
	
	uint32_t* instruction = guest_flat_to_host(vcpu->kvm, pc);
	if (!host_ptr_in_ram(vcpu->kvm, instruction + 1))
		die("SingleStep requesting instruction outside memory");
	
#ifdef CONFIG_HAS_OPCODES
	opcode = disassemble((uint8_t*)instruction, 4);
	char* tmp = opcode;
	while(*tmp != '\0') {
		if (*tmp =='\t') *tmp=' ';
		tmp++;
	}
#endif
	
#ifdef CONFIG_HAS_BFD
	psym = symbol_lookup(vcpu->kvm, pc - 0x0000000080080000, sym, MAX_SYM_LEN);
#endif
	
	dprintf(debug_fd, "0x%012lx: %08x  %-42s ; %s\n", pc, *instruction, opcode != NULL ? opcode : "", (IS_ERR(psym) || psym== NULL) ? "" : psym);
	
#ifdef CONFIG_HAS_OPCODES
	if (opcode != NULL) free(opcode);
#endif
	
}

void kvm_cpu__show_registers(struct kvm_cpu *vcpu)
{
	struct kvm_one_reg reg;
	unsigned long data;
	int debug_fd = kvm_cpu__get_debug_fd();

	reg.addr = (u64)&data;
	dprintf(debug_fd, "\n Registers:\n");

	reg.id		= ARM64_CORE_REG(regs.pc);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (pc)");
	dprintf(debug_fd, " PC:    0x%lx\n", data);

	reg.id		= ARM64_CORE_REG(regs.pstate);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (pstate)");
	dprintf(debug_fd, " PSTATE:    0x%lx\n", data);

	reg.id		= ARM64_CORE_REG(sp_el1);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (sp_el1)");
	dprintf(debug_fd, " SP_EL1:    0x%lx\n", data);

	reg.id		= ARM64_CORE_REG(regs.regs[30]);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (lr)");
	dprintf(debug_fd, " LR:    0x%lx\n", data);
}


bool kvm_cpu__handle_exit(struct kvm_cpu *vcpu)
{
	u64 esr_el2, fault_ipa;
	u64 pc, elr_el1;
	int debug_fd = kvm_cpu__get_debug_fd();
	u8 ec;

	struct kvm_one_reg reg;
	u64 data = 0;

	if (vcpu->kvm_run->exit_reason != KVM_EXIT_ARM_RAW_MODE) return true;
	
	esr_el2 = vcpu->kvm_run->arm_raw.esr_el2;
	fault_ipa = vcpu->kvm_run->arm_raw.fault_ipa;
	ec = (esr_el2 >> 26) & 0x3F;

	
	reg.id   = ARM64_CORE_REG(regs.pc);
	reg.addr = (u64)&data;
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (pc)");
	pc=data;

	reg.id   = ARM64_CORE_REG(elr_el1);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (ELR_EL1)");
	elr_el1=data;

	dprintf(debug_fd, "\nRAW @PC=%llx\n", pc);
	dprintf(debug_fd, "    ESR_EL2=%llx\n", esr_el2);
	dprintf(debug_fd, "        EC=%x\n", ec);
	dprintf(debug_fd, "    IPA=%llx\n", fault_ipa);
	dprintf(debug_fd, "    ELR_EL1=%llx\n", elr_el1);

	switch(ec) {
		
		case HVC_EXCEPTION:
		{
			u16 hvc_id = esr_el2 & 0xFFFF;
			dprintf(debug_fd, "HVC #%d ignored\n", hvc_id);
			// HVC is one of the few instructions that are trapped
			// and for wich the PC is already set after the instr.
			return true;
		}
		break;
		
		default:
			return false;
			
	}
	/*
	// lets pretend the PC is at the instruction that caused the problem
	data	= elr_el1;
	reg.id	= ARM64_CORE_REG(regs.pc);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (pc)");

	return false;
	 */

}
