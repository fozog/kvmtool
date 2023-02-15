#ifndef INCLUDE_SYS_REGS
#define INCLUDE_SYS_REGS


#include "kvm/kvm.h"
#include "kvm/kvm-cpu.h"
 

#define KVM_SYSREG_FROM_AARCH64(x)	((x) | KVM_REG_ARM64 | KVM_REG_ARM64_SYSREG | (KVM_REG_SIZE_U64))

typedef uint16_t sys_reg_t;
typedef uint8_t reg_t;
struct sys_reg_info;

typedef int (*formatter_f)(sys_reg_t reg, u64 value, int spacing, detail_t detail);

typedef vmm_action_t (*getter_f)(struct kvm* context, struct kvm_cpu* vcore, reg_t reg, struct sys_reg_info* sys_reg);
typedef vmm_action_t (*setter_f)(struct kvm* context, struct kvm_cpu* vcore, struct sys_reg_info* sys_reg, reg_t reg);

/* sys_regs table */
typedef struct sys_reg_info {
	sys_reg_t	id;
	uint64_t        reset_value;
	uint64_t        minimal_el;
	const char*     name;
	const char*     description;
	formatter_f     formatter;
	getter_f        read;
	setter_f        write;
} sys_reg_info_t;


static inline u64 vcore_get_sysreg(struct kvm_cpu* vcpu, sys_reg_t reg)
{
	u64 data;
	struct kvm_one_reg kvm_reg;
	kvm_reg.addr = (u64)&data;
	kvm_reg.id	= KVM_SYSREG_FROM_AARCH64(reg);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &kvm_reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (spsr[EL1])");
	return data;
}

int vcore_get_sys_reg_count(void);
int vcore_get_index(sys_reg_t reg);

#endif

