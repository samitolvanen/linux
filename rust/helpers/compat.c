// SPDX-License-Identifier: GPL-2.0

#include <linux/compat.h>

__rust_helper bool rust_helper_in_compat_syscall(void)
{
	return in_compat_syscall();
}
