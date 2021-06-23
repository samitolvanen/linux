/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PROTO_H
#define _ASM_X86_PROTO_H

#include <linux/linkage.h>
#include <asm/ldt.h>

struct task_struct;

/* misc architecture specific prototypes */

void syscall_init(void);

#ifdef CONFIG_X86_64
DECLARE_ASM_FUNC_SYMBOL(entry_SYSCALL_64);
DECLARE_ASM_FUNC_SYMBOL(entry_SYSCALL_64_safe_stack);
long do_arch_prctl_64(struct task_struct *task, int option, unsigned long arg2);
#endif

#ifdef CONFIG_X86_32
DECLARE_ASM_FUNC_SYMBOL(entry_INT80_32);
DECLARE_ASM_FUNC_SYMBOL(entry_SYSENTER_32);
DECLARE_ASM_FUNC_SYMBOL(__begin_SYSENTER_singlestep_region);
DECLARE_ASM_FUNC_SYMBOL(__end_SYSENTER_singlestep_region);
#endif

#ifdef CONFIG_IA32_EMULATION
DECLARE_ASM_FUNC_SYMBOL(entry_SYSENTER_compat);
DECLARE_ASM_FUNC_SYMBOL(__end_entry_SYSENTER_compat);
DECLARE_ASM_FUNC_SYMBOL(entry_SYSCALL_compat);
DECLARE_ASM_FUNC_SYMBOL(entry_SYSCALL_compat_safe_stack);
DECLARE_ASM_FUNC_SYMBOL(entry_INT80_compat);
#ifdef CONFIG_XEN_PV
DECLARE_ASM_FUNC_SYMBOL(xen_entry_INT80_compat);
#endif
#endif

void x86_configure_nx(void);
void x86_report_nx(void);

extern int reboot_force;

long do_arch_prctl_common(struct task_struct *task, int option,
			  unsigned long cpuid_enabled);

#endif /* _ASM_X86_PROTO_H */
