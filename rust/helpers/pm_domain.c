// SPDX-License-Identifier: GPL-2.0

#include <linux/pm_domain.h>

/*
 * The "inline" implementation of the helper below is only available when
 * CONFIG_PM is not set. When it is set, the function is exported and bound
 * directly.
 */
#ifndef CONFIG_PM
__rust_helper int
rust_helper_devm_pm_domain_attach_list(struct device *dev,
				       const struct dev_pm_domain_attach_data *data,
				       struct dev_pm_domain_list **list)
{
	return devm_pm_domain_attach_list(dev, data, list);
}
#endif
