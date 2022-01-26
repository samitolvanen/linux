// SPDX-License-Identifier: GPL-2.0
/*
 * Clang Control Flow Integrity (CFI) error handling.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/cfi.h>

/* Returns the target of the indirect call that follows the trap in `addr`. */
void * __weak arch_get_cfi_target(unsigned long addr, struct pt_regs *regs)
{
	return NULL;
}

#ifdef CONFIG_MODULES
/* Populates `kcfi_trap(_end)?` fields in `struct module`. */
void module_cfi_finalize(const Elf_Ehdr *hdr, const Elf_Shdr *sechdrs,
			 struct module *mod)
{
	char *secstrings;
	unsigned int i;

	mod->kcfi_traps = NULL;
	mod->kcfi_traps_end = NULL;

	secstrings = (char *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	for (i = 1; i < hdr->e_shnum; i++) {
		if (strcmp(secstrings+sechdrs[i].sh_name, "__kcfi_traps"))
			continue;

		mod->kcfi_traps = (unsigned long *)sechdrs[i].sh_addr;
		mod->kcfi_traps_end = (unsigned long *)(sechdrs[i].sh_addr + sechdrs[i].sh_size);
		break;
	}
}

static bool is_module_cfi_trap(unsigned long addr)
{
	bool found = false;
	struct module *mod;
	unsigned long *p;

	rcu_read_lock_sched_notrace();

	mod = __module_address(addr);
	if (mod)
		for (p = mod->kcfi_traps; !found && p < mod->kcfi_traps_end; ++p)
			found = (*p == addr);

	rcu_read_unlock_sched_notrace();

	return found;
}

#else /* CONFIG_MODULES */

static inline bool is_module_cfi_trap(unsigned long addr)
{
	return false;
}

#endif /* CONFIG_MODULES */

extern unsigned long __start___kcfi_traps[];
extern unsigned long __stop___kcfi_traps[];

static bool is_cfi_trap(unsigned long addr)
{
	unsigned long *p;

	for (p = __start___kcfi_traps; p < __stop___kcfi_traps; ++p)
		if (*p == addr)
			return true;

	return is_module_cfi_trap(addr);
}

#define __CFI_ERROR_FMT "CFI failure at %pS (target: %pS)\n"

static enum bug_trap_type __report_cfi(void *addr, void *target, struct pt_regs *regs)
{
	if (IS_ENABLED(CONFIG_CFI_PERMISSIVE)) {
		pr_warn(__CFI_ERROR_FMT, addr, target);
		__warn(NULL, 0, addr, 0, regs, NULL);

		return BUG_TRAP_TYPE_WARN;
	} else {
		pr_crit(__CFI_ERROR_FMT, addr, target);
		return BUG_TRAP_TYPE_BUG;
	}
}

enum bug_trap_type report_cfi(unsigned long addr, struct pt_regs *regs)
{
	if (!is_cfi_trap(addr))
		return BUG_TRAP_TYPE_NONE;

	return __report_cfi((void *)addr, arch_get_cfi_target(addr, regs), regs);
}
