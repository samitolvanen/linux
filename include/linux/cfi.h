/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Clang Control Flow Integrity (CFI) support.
 *
 * Copyright (C) 2022 Google LLC
 */
#ifndef _LINUX_CFI_H
#define _LINUX_CFI_H

#include <linux/bug.h>
#include <linux/module.h>

#ifdef CONFIG_CFI_CLANG

#ifdef CONFIG_MODULES
void module_cfi_finalize(const Elf_Ehdr *hdr, const Elf_Shdr *sechdrs, struct module *mod);
#endif

void *arch_get_cfi_target(unsigned long addr, struct pt_regs *regs);
enum bug_trap_type report_cfi(unsigned long addr, struct pt_regs *regs);
#else

#ifdef CONFIG_MODULES
static inline void module_cfi_finalize(const Elf_Ehdr *hdr, const Elf_Shdr *sechdrs,
				       struct module *mod) {}
#endif

static inline enum bug_trap_type report_cfi(unsigned long addr, struct pt_regs *regs)
{
	return BUG_TRAP_TYPE_NONE;
}
#endif /* CONFIG_CFI_CLANG */

#endif /* _LINUX_CFI_H */
