// SPDX-License-Identifier: GPL-2.0

#include <linux/nvmem-consumer.h>

/*
 * The "inline" implementations of the helpers below are only available when
 * CONFIG_NVMEM is not set. When it is set, the functions are exported and
 * bound directly.
 */
#ifndef CONFIG_NVMEM
__rust_helper struct nvmem_cell *rust_helper_nvmem_cell_get(struct device *dev,
							    const char *id)
{
	return nvmem_cell_get(dev, id);
}

__rust_helper void *rust_helper_nvmem_cell_read(struct nvmem_cell *cell,
						size_t *len)
{
	return nvmem_cell_read(cell, len);
}

__rust_helper void rust_helper_nvmem_cell_put(struct nvmem_cell *cell)
{
	nvmem_cell_put(cell);
}
#endif
