#include <stdlib.h>

#include "asm/kvm.h"
#include "kvm/kvm-arch.h"

#include "kvm/kvm.h"
#include "asm/sys_regs.h"
#include "kvm/vcore_sys_regs_print.h"
#include "kvm/vcore_sys_regs.h"

#define DECLARE_REGISTER(name) \
vmm_action_t name ## _read(struct kvm* context, struct kvm_cpu* vcore, reg_t reg, sys_reg_info_t* sys_reg); \
vmm_action_t name ## _write(struct kvm* context, struct kvm_cpu* vcore, sys_reg_info_t* sys_reg, reg_t reg);

//#define DEBUG_HASHTABLE

/*
// defined in gic-v3.c
 DECLARE_REGISTER(gic_icc_ctlr)
 DECLARE_REGISTER(gic_icc_pmr)
 DECLARE_REGISTER(gic_icc_bpr)
 DECLARE_REGISTER(gic_icc_igrpen1)
 DECLARE_REGISTER(gic_icc_iar1_el1)
IMPORT_REGISTER(gic_icc_eoir1_el1)

// defined in vcore_emulate.c
 DECLARE_REGISTER(SP_EL1)
 DECLARE_REGISTER(SCTLR_EL3)
 DECLARE_REGISTER(VBAR_EL3)
 DECLARE_REGISTER(MAIR_EL3)
 DECLARE_REGISTER(TCR_EL3)
 DECLARE_REGISTER(TTBR0_EL3)
 DECLARE_REGISTER(SCR_EL3)
 DECLARE_REGISTER(CPTR_EL3)
*/

DECLARE_REGISTER(IGNORE)
DECLARE_REGISTER(CNTPCT_EL0)
DECLARE_REGISTER(VBAR_EL1)
DECLARE_REGISTER(ID_AA64ISAR2)
DECLARE_REGISTER(ID_AA64SMFR0_EL1)
DECLARE_REGISTER(ID_AA64ISAR2_EL1)
DECLARE_REGISTER(SP_EL1)


vmm_action_t IGNORE_read(struct kvm* context, struct kvm_cpu* vcore, reg_t reg, sys_reg_info_t* sys_reg) {
    return VMM_CONTINUE;
}

vmm_action_t IGNORE_write(struct kvm* context, struct kvm_cpu* vcore, sys_reg_info_t* sys_reg, reg_t reg) {
    return VMM_CONTINUE;
}

vmm_action_t CNTPCT_EL0_read(struct kvm* context, struct kvm_cpu* vcore, reg_t reg, sys_reg_info_t* sys_reg) {
   /*volatile u64 value;
    asm("mrs %0, CNTPCT_EL0; isb": "=r" (value));
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);*/
    return VMM_CONTINUE;
}

vmm_action_t VBAR_EL1_read(struct kvm* context, struct kvm_cpu* vcore, reg_t reg, sys_reg_info_t* sys_reg)
{
    //hv_vcpu_set_reg(vcore->vcpu_handle, reg, vcore->vbar_el1);
    //printf("x%d = VBAR_EL1 (%llx)\n", reg, vcore->vbar_el1);
    return VMM_CONTINUE;
}

vmm_action_t VBAR_EL1_write(struct kvm* context, struct kvm_cpu* vcore, sys_reg_info_t* sys_reg, reg_t reg)
{
    /*u64 value;
    hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
    printf("VBAR_EL1 = x%d (%llx)", reg, value);
    vcore->vbar_el1 = value;*/
    return VMM_CONTINUE;
}

vmm_action_t ID_AA64ISAR2_EL1_read(struct kvm* context, struct kvm_cpu* vcore, reg_t reg, sys_reg_info_t* sys_reg)
{
	/*
    // not defined for the moment
    hv_vcpu_set_reg(vcore->vcpu_handle, reg, 0);*/
    return VMM_CONTINUE;
}

vmm_action_t ID_AA64SMFR0_EL1_read(struct kvm* context, struct kvm_cpu* vcore, reg_t reg, sys_reg_info_t* sys_reg)
{
    // not defined for the moment
    /*hv_vcpu_set_reg(vcore->vcpu_handle, reg, 0);*/
    return VMM_CONTINUE;
}

vmm_action_t SP_EL1_write(struct kvm* context, struct kvm_cpu* vcore, sys_reg_info_t* sys_reg, reg_t reg)
{
	/*
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
	uint64_t value;
	hv_vcpu_get_reg(vcore->vcpu_handle, reg, &value);
	sys_reg->value = value;
	hv_vcpu_set_sys_reg(vcore->vcpu_handle, HV_SYS_REG_SP_EL1, value);
    }*/
    return VMM_CONTINUE;
}

vmm_action_t SP_EL1_read(struct kvm* context, struct kvm_cpu* vcore, reg_t reg, sys_reg_info_t* sys_reg)
{/*
    if (vcore_get_current_el(vcore) >= sys_reg->minimal_el) {
	uint64_t value;
	value = sys_reg->value;
	hv_vcpu_set_reg(vcore->vcpu_handle, reg, value);
    }*/
    return VMM_CONTINUE;
}


int vcore_sys_reg_table_count = 0;
sys_reg_hnode_t vcore_sys_reg_table[SYS_REG_HASHTABLE_CAPACITY];

int vcore_get_sys_reg_count(void)
{
    return vcore_sys_reg_table_count;
}

/*
 There are 1067 registers, we want to minimize the number of tests to find
 a register. Let's use a 1024 entries hash table: 10 bits are needed.
 Based on encondings that have high bit of op0 always 1 and the fact that CRm
 and op2 are often used to have indexes of register sets (DBG registers for instance).
 <enc n="op0" v="0b10"/>
 <enc n="op1" v="0b000"/>
 <enc n="CRn" v="0b0000"/>
 <enc n="CRm" v="m[3:0]"/>
 <enc n="op2" v="0b101"/>
 Let's use bits: 2, 5, 7-14
*/
static int vcore_sysreg_hash(sys_reg_t reg)
{
	int result = (reg >> 0) & 0b11;
	result |= ((reg >> 5) & 0b11) << 2;
	result |= ((reg >> 7) & 0b111111) << 4;
	return result;
}

sys_reg_info_t* vcore_sysreg_get_byid(sys_reg_t reg_id)
{
	int bucket = (vcore_sysreg_hash(reg_id) & 0x3FF) + 1;
	sys_reg_hnode_t* current = &vcore_sys_reg_table[bucket];
	while(current != NULL && current->reg.id != reg_id) {
		current = current->next;
	}
	if (current != NULL) {
		if (current->reg.id == reg_id) return &current->reg;
	}
	return NULL;
}

#ifdef DEBUG_HASHTABLE
static sys_reg_info_t* vcore_sysreg_get_byid_introspection(sys_reg_t reg_id, int*  count)
{
	int bucket = (vcore_sysreg_hash(reg_id) & 0x3FF) + 1;
	sys_reg_hnode_t* current = &vcore_sys_reg_table[bucket];
	while(current != NULL && current->reg.id != reg_id) {
		current = current->next;
		(*count)++;
	}
	if (current != NULL) {
		(*count)++;
		if (current->reg.id == reg_id) return &current->reg;
	}
	return NULL;
}
#endif

/* returns the number of added registers */
static int order=0;
static sys_reg_hnode_t* last = NULL;
static int add_reg(sys_reg_t reg_id, u8 minimal_el, const char* name, const char* description)
{
	// make sure index is in range of capacity and keep index 0 special
	int bucket = (vcore_sysreg_hash(reg_id) +1) & 0x3FF;
	sys_reg_hnode_t* head = &vcore_sys_reg_table[bucket];
	sys_reg_hnode_t* current = head;
	sys_reg_hnode_t* prev = NULL;
	
#ifdef DEBUG_HASHTABLE
	fprintf(stderr, "bucket[%d]@%p: %s\n", bucket, head, name);
#endif
	if (current->reg.id == reg_id) return 0;
	
	while(current->next != NULL) {
		if (current->reg.id == reg_id) return 0;
		prev = current;
		current = current->next;
	}
	//fprintf(stderr, "    not found\n");
	// if we are not on the head
	bool add = false;
	if (current == NULL) {
		if (prev != head) {
			add = true;
		}
		else {
			// bucket empty
			current = head;
		}
	}
	else {
		if (current->reg.id != reg_id) {
			// head bucket non empty
			add=true;
		}
	}
	if (add) {
		//fprintf(stderr, "    alloc\n");
		current->next = malloc(sizeof(sys_reg_hnode_t));
		if (current->next == NULL) {
			die("Could not add register %s\n", name);
		}
		memset(current->next, 0, sizeof(sys_reg_hnode_t));
		current = current->next;
	}
	//fprintf(stderr, "    install @%p\n", current);

	current->reg.id = reg_id;
	current->reg.minimal_el = minimal_el;
	current->reg.name = name;
	current->reg.description = description;
	current->order = order++;
	if (last != NULL) last->order_next_bucket = bucket;
	last = current;
	return 1;
}

#if 1

#include "./sys_regs.c"

#else

static int add_sysregs(void)
{
	int i = 0;
	i += add_reg(AARCH64_TRCSSCCR_0, 1, AARCH64_TRCSSCCR_0_NAME, AARCH64_TRCSSCCR_0_DESC);
	i += add_reg(AARCH64_TRCSSCCR_1, 1, AARCH64_TRCSSCCR_1_NAME, AARCH64_TRCSSCCR_1_DESC);
	i += add_reg(AARCH64_TRCSSCCR_2, 1, AARCH64_TRCSSCCR_2_NAME, AARCH64_TRCSSCCR_2_DESC);
	i += add_reg(AARCH64_TRCSSCCR_3, 1, AARCH64_TRCSSCCR_3_NAME, AARCH64_TRCSSCCR_3_DESC);
	i += add_reg(AARCH64_TTBR0_EL1, 1, AARCH64_TTBR0_EL1_NAME, AARCH64_TTBR0_EL1_DESC);
	return i;
}
#endif

static int vcore_sys_regs__init(struct kvm *kvm)
{
	memset(vcore_sys_reg_table, 0, sizeof(vcore_sys_reg_table));
	// use the generated code
	vcore_sys_reg_table_count = add_sysregs();
#ifdef DEBUG_HASHTABLE
	int bucket;
	int occupation[256] = {0};
	for (bucket = 0; bucket < SYS_REG_HASHTABLE_CAPACITY; bucket++) {
		sys_reg_hnode_t* current = &vcore_sys_reg_table[bucket];
		int count = 0;
		if (current->reg.id != 0) count++;
		while(current->next != NULL) {
			count++;
			current = current->next;
		}
		occupation[count]++;
		if (count == 0) {
			//printf("Bucket[%d]:\n", bucket);
		}
		else {
			//fprintf(stderr, "Bucket[%d]: %d\n", bucket, count);
		}
	}
	int i;
	int total = 0;
	for(i = 0; i < 256; i++) {
		total += i * occupation[i];
		if (occupation[i] != 0) fprintf(stderr, "Buckets with %d entries: %d, current coverage: %d\n", i, occupation[i], total);
	}
	
	int v = 0;
	sys_reg_info_t* reg = vcore_sysreg_get_byid_introspection(AARCH64_TTBR0_EL1, &v);
	fprintf(stderr, "%s access in %d tests\n", reg->name, v);
#endif
	
	return 0;
}
late_init(vcore_sys_regs__init)
