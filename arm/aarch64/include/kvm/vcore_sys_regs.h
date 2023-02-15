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
	u64        	reset_value;
	u64        	minimal_el;
	const char*     name;
	const char*     description;
	formatter_f     formatter;
	getter_f        read;
	setter_f        write;
} sys_reg_info_t;

/* hash table for sys_regs*/
struct sys_reg_hnode;
typedef struct sys_reg_hnode {
	struct sys_reg_hnode* next;
	sys_reg_info_t	reg;
	u16		order;			// pretty print
	u16		order_next_bucket;	// pretty print
} sys_reg_hnode_t;


// lets make sure that the combination of vcore_sys_reg in hashtable is
// 64 bytes long.
typedef struct vcore_sys_reg {
	union {
		struct {
			sys_reg_t	id;
			uint64_t        value;
			getter_f        read;			// cached
			setter_f        write;			// cached
		};
		__u64	padding[7];
	};
} vcore_sys_reg_t;

/* hash table for vcore_sys_regs */
struct vcore_sys_reg_hnode;
typedef struct vcore_sys_reg_hnode {
	struct vcore_sys_reg_hnode* next;
	vcore_sys_reg_t sysreg;
} vcore_sys_reg_hnode_t;

//must be a power of two
#define SYS_REG_HASHTABLE_CAPACITY	2048

static inline u64 vcore_read_sysreg_fromkvm(struct kvm_cpu* vcpu, sys_reg_t reg)
{
	u64 data;
	struct kvm_one_reg kvm_reg;
	kvm_reg.addr = (u64)&data;
	kvm_reg.id	= KVM_SYSREG_FROM_AARCH64(reg);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &kvm_reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (spsr[EL1])");
	return data;
}

sys_reg_info_t* vcore_sysreg_get_next(sys_reg_info_t* current);
sys_reg_info_t* vcore_sysreg_get_first(void);
int vcore_get_sys_reg_count(void);
sys_reg_info_t*  vcore_sysreg_get_byid(sys_reg_t reg);

#endif

