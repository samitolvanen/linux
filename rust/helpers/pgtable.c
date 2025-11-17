// SPDX-License-Identifier: GPL-2.0

#include <linux/pgtable.h>

pgprot_t rust_helper_pgprot_noncached(pgprot_t prot)
{
	return pgprot_noncached(prot);
}