// SPDX-License-Identifier: GPL-2.0

#include <linux/capability.h>

/*
 * The "inline" implementation of capable() is only available when
 * CONFIG_MULTIUSER isn't set.
 */
#ifndef CONFIG_MULTIUSER
__rust_helper bool rust_helper_capable(int cap)
{
	return capable(cap);
}
#endif
