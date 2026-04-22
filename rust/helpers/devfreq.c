// SPDX-License-Identifier: GPL-2.0

#include <linux/devfreq.h>
#include <linux/devfreq_cooling.h>

/*
 * devfreq_cooling_em_register() and devfreq_cooling_unregister() are static
 * inline when CONFIG_DEVFREQ_THERMAL is not set. Wrap them so Rust bindings
 * are available regardless of that config.
 */
#ifndef CONFIG_DEVFREQ_THERMAL
__rust_helper struct thermal_cooling_device *
rust_helper_devfreq_cooling_em_register(struct devfreq *df,
					struct devfreq_cooling_power *dfc_power)
{
	return devfreq_cooling_em_register(df, dfc_power);
}

__rust_helper void
rust_helper_devfreq_cooling_unregister(struct thermal_cooling_device *dfc)
{
	devfreq_cooling_unregister(dfc);
}
#endif
