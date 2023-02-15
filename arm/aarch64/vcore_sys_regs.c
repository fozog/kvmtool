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


#include "./sys_regs.c"

int vcore_get_sys_reg_count(void)
{
    return sizeof(sys_regs) / sizeof(sys_reg_info_t);
}

int vcore_get_index(sys_reg_t reg)
{
    int i;
    int register_count = vcore_get_sys_reg_count();
    for(i = 0; i < register_count; i++) {
	if (sys_regs[i].id == reg) return i;
    }
    return -EINVAL;
}
