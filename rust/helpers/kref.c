// SPDX-License-Identifier: GPL-2.0

#include <linux/kref.h>

__rust_helper unsigned int rust_helper_kref_read(const struct kref *kref)
{
	return kref_read(kref);
}
