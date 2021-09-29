// SPDX-License-Identifier: GPL-2.0
/*
 * Runtime Shadow Call Stack patching.
 *
 * Copyright (C) 2021 Google LLC
 */

#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/scs.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/insn.h>
#include <asm/scs.h>

__noscs
static bool __scs_patch(const s32 *start, const s32 *end, bool is_module)
{
	const s32 *p;
	u32 insn_paciasp;
	u32 insn_autiasp;
	u32 insn_scs_str;
	u32 insn_scs_ldr;

	if (system_supports_address_auth())
		return false;

	insn_paciasp = aarch64_insn_gen_hint(AARCH64_INSN_HINT_PACIASP);
	insn_autiasp = aarch64_insn_gen_hint(AARCH64_INSN_HINT_AUTIASP);
	insn_scs_str = aarch64_insn_gen_load_store_imm(
				AARCH64_INSN_REG_LR,
				AARCH64_INSN_REG_18,
				8,
				AARCH64_INSN_SIZE_64,
				AARCH64_INSN_LDST_STORE_REG_POST_INDEX);
	insn_scs_ldr = aarch64_insn_gen_load_store_imm(
				AARCH64_INSN_REG_LR,
				AARCH64_INSN_REG_18,
				(u64)-8,
				AARCH64_INSN_SIZE_64,
				AARCH64_INSN_LDST_LOAD_REG_PRE_INDEX);

	for (p = start; p < end; p++) {
		__le32 *ptr = (u32 *)offset_to_ptr(p);
		u32 insn = le32_to_cpu(*ptr);

		if (!is_module)
			ptr = lm_alias(ptr);

		if (insn == insn_paciasp)
			*ptr = cpu_to_le32(insn_scs_str);
		else if (insn == insn_autiasp)
			*ptr = cpu_to_le32(insn_scs_ldr);
		else
			WARN_ONCE(1, "scs: found unexpected instruction %08x", insn);

		if (!is_module)
			__flush_dcache_area(ptr, sizeof(u32));
	}

	return true;
}

void __init scs_patch_boot(void)
{
	WARN_ON(smp_processor_id() != 0);

	if (__scs_patch(__scs_sites, __scs_sites_end, false)) {
		dsb(ish);
		__flush_icache_all();
		isb();
		pr_info("scs: enabled at runtime\n");
	} else
		scs_disable();
}

#ifdef CONFIG_MODULES
void scs_patch_module(void *start, size_t length)
{
	__scs_patch(start, (const s32 *)(start + length), true);
}
#endif
