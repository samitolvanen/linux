// SPDX-License-Identifier: GPL-2.0

#include <linux/math64.h>

__rust_helper u64 rust_helper_div_u64(u64 dividend, u32 divisor)
{
	return div_u64(dividend, divisor);
}

__rust_helper u64 rust_helper_div_u64_rem(u64 dividend, u32 divisor,
					  u32 *remainder)
{
	return div_u64_rem(dividend, divisor, remainder);
}
