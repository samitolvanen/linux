// SPDX-License-Identifier: GPL-2.0

#include <linux/highmem.h>

__rust_helper void rust_helper_flush_kernel_vmap_range(void *vaddr, int size)
{
	flush_kernel_vmap_range(vaddr, size);
}

__rust_helper void rust_helper_invalidate_kernel_vmap_range(void *vaddr,
							    int size)
{
	invalidate_kernel_vmap_range(vaddr, size);
}
