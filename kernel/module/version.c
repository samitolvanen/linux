// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Module version support
 *
 * Copyright (C) 2008 Rusty Russell
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <crypto/sha2.h>
#include "internal.h"

/*
 * For symbol names longer than MODULE_NAME_LEN, the version table includes
 * a hash of the symbol name in the following format:
 *
 * <hash name>\0<binary hash of the symbol name>
 */
#define SYMHASH_PREFIX		"sha256"
#define SYMHASH_PREFIX_LEN	sizeof(SYMHASH_PREFIX) /* includes \0 */
#define SYMHASH_LEN		(SYMHASH_PREFIX_LEN + SHA256_DIGEST_SIZE)

static void symhash(const char *name, size_t len, u8 hash[SYMHASH_LEN])
{
	memcpy(hash, SYMHASH_PREFIX, SYMHASH_PREFIX_LEN);
	sha256(name, len, &hash[SYMHASH_PREFIX_LEN]);
}

static int symcmp(const char *version_name, const char *name, size_t len,
		  const u8 *hash)
{
	BUILD_BUG_ON(SYMHASH_LEN > MODULE_NAME_LEN);

	if (len >= MODULE_NAME_LEN)
		return memcmp(version_name, hash, SYMHASH_LEN);

	return strcmp(version_name, name);
}

int check_version(const struct load_info *info,
		  const char *symname,
			 struct module *mod,
			 const s32 *crc)
{
	Elf_Shdr *sechdrs = info->sechdrs;
	unsigned int versindex = info->index.vers;
	unsigned int i, num_versions;
	struct modversion_info *versions;
	u8 hash[SYMHASH_LEN];
	size_t len;

	/* Exporting module didn't supply crcs?  OK, we're already tainted. */
	if (!crc)
		return 1;

	/* No versions at all?  modprobe --force does this. */
	if (versindex == 0)
		return try_to_force_load(mod, symname) == 0;

	versions = (void *)sechdrs[versindex].sh_addr;
	num_versions = sechdrs[versindex].sh_size
		/ sizeof(struct modversion_info);

	len = strlen(symname);

	/* For symbols with a long name, use the hash format. */
	if (len >= MODULE_NAME_LEN)
		symhash(symname, len, hash);

	for (i = 0; i < num_versions; i++) {
		u32 crcval;

		if (symcmp(versions[i].name, symname, len, hash) != 0)
			continue;

		crcval = *crc;
		if (versions[i].crc == crcval)
			return 1;
		pr_debug("Found checksum %X vs module %lX\n",
			 crcval, versions[i].crc);
		goto bad_version;
	}

	/* Broken toolchain. Warn once, then let it go.. */
	pr_warn_once("%s: no symbol version for %s\n", info->name, symname);
	return 1;

bad_version:
	pr_warn("%s: disagrees about version of symbol %s\n", info->name, symname);
	return 0;
}

int check_modstruct_version(const struct load_info *info,
			    struct module *mod)
{
	struct find_symbol_arg fsa = {
		.name	= "module_layout",
		.gplok	= true,
	};

	/*
	 * Since this should be found in kernel (which can't be removed), no
	 * locking is necessary -- use preempt_disable() to placate lockdep.
	 */
	preempt_disable();
	if (!find_symbol(&fsa)) {
		preempt_enable();
		BUG();
	}
	preempt_enable();
	return check_version(info, "module_layout", mod, fsa.crc);
}

/* First part is kernel version, which we ignore if module has crcs. */
int same_magic(const char *amagic, const char *bmagic,
	       bool has_crcs)
{
	if (has_crcs) {
		amagic += strcspn(amagic, " ");
		bmagic += strcspn(bmagic, " ");
	}
	return strcmp(amagic, bmagic) == 0;
}

/*
 * Generate the signature for all relevant module structures here.
 * If these change, we don't want to try to parse the module.
 */
void module_layout(struct module *mod,
		   struct modversion_info *ver,
		   struct kernel_param *kp,
		   struct kernel_symbol *ks,
		   struct tracepoint * const *tp)
{
}
EXPORT_SYMBOL(module_layout);
