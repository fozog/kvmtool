/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */

#ifndef cpuinfo_h
#define cpuinfo_h

#include "kvm/kvm.h"
#include "kvm/vcore_sys_regs.h"


struct vcore;

int dbg_cr(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int dfr0_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int dfr1_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int esr_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int esr_el2(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int isar0_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int isar1_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int mfr0_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int mfr1_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int mfr2_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int pfr0_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int pfr1_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int tcr_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int tcr_el3(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int scr_el3(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int sctlr_el1(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int sctlr_el3(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int MAIR_EL1(sys_reg_t reg, u64 value, int spacing, detail_t detail);

int vcore_print_sys_reg(sys_reg_t reg, u64 value, int spacing, detail_t detail);
int vcore_print_sys_regs(struct kvm_cpu* vcore, int spacing, detail_t detail);
int vcore_print_general_regs(struct kvm_cpu* vcore, int spacing);
const char* vcore_get_sys_reg_name(sys_reg_t reg);
const char* vcore_get_sys_reg_desc(sys_reg_t reg);

#endif /* cpuinfo_h */

