/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_SCS_H
#define _ASM_SCS_H

#ifdef __ASSEMBLY__

#include <asm/asm-offsets.h>

#ifdef CONFIG_SHADOW_CALL_STACK
	scs_sp	.req	x18

	.macro scs_load tsk, tmp
	ldr	scs_sp, [\tsk, #TSK_TI_SCS_SP]
	.endm

	.macro scs_save tsk, tmp
	str	scs_sp, [\tsk, #TSK_TI_SCS_SP]
	.endm
#else
	.macro scs_load tsk, tmp
	.endm

	.macro scs_save tsk, tmp
	.endm
#endif /* CONFIG_SHADOW_CALL_STACK */

#else

#ifdef CONFIG_SHADOW_CALL_STACK_PATCHING
extern const s32 __scs_sites[];
extern const s32 __scs_sites_end[];

extern void __init scs_patch_boot(void);
extern void scs_patch_module(void *start, size_t length);
#else
static inline void scs_patch_boot(void) {}
static inline void scs_patch_module(void *start, size_t length) {}
#endif

#endif /* __ASSEMBLY __ */

#endif /* _ASM_SCS_H */
