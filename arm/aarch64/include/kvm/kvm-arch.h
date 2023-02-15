#ifndef KVM__KVM_ARCH_H
#define KVM__KVM_ARCH_H

#include <linux/sizes.h>

struct kvm;
unsigned long long kvm__arch_get_kern_offset(struct kvm *kvm, int fd);
int kvm__arch_get_ipa_limit(struct kvm *kvm);
void kvm__arch_enable_mte(struct kvm *kvm);
void kvm__arch_enable_raw_mode(struct kvm *kvm);

#define MAX_PAGE_SIZE	SZ_64K

#define ARCH_HAS_CFG_RAM_ADDRESS	1

#include "arm-common/kvm-arch.h"

typedef  enum {
    VMM_CONTINUE,
    VMM_EXIT_REQUESTED,
    VMM_ABORT_REQUESTED
} vmm_action_t;

#endif /* KVM__KVM_ARCH_H */
