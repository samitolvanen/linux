// SPDX-License-Identifier: GPL-2.0

#include <linux/nvmem-consumer.h>

/*
 * The "inline" implementation of the helper below is only available when
 * CONFIG_NVMEM is not set. When it is set, the function is exported and bound
 * directly.
 */
#ifndef CONFIG_NVMEM
__rust_helper int rust_helper_nvmem_cell_read_variable_le_u64(struct device *dev,
							      const char *cell_id,
							      u64 *val)
{
	return nvmem_cell_read_variable_le_u64(dev, cell_id, val);
}
#endif
