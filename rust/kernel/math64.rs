// SPDX-License-Identifier: GPL-2.0

//! 64-bit integer division.
//!
//! C header: [`include/linux/math64.h`](srctree/include/linux/math64.h)
//!
//! 32-bit architectures do not implement 64-by-64 division, so `u64 / u64` fails to link
//! there. Division by a 32-bit divisor works everywhere.

use core::num::NonZero;

use crate::bindings;

/// Divides a 64-bit dividend by a 32-bit divisor.
///
/// # Examples
///
/// ```
/// use core::num::NonZero;
/// use kernel::math64::div_u64;
///
/// assert_eq!(div_u64(1_500_000_000, NonZero::new(1_000_000_000).unwrap()), 1);
/// ```
#[inline]
pub fn div_u64(dividend: u64, divisor: NonZero<u32>) -> u64 {
    // SAFETY: The divisor is nonzero, as `div_u64()` requires.
    unsafe { bindings::div_u64(dividend, divisor.get()) }
}

/// Divides a 64-bit dividend by a 32-bit divisor, returning the quotient and the remainder.
///
/// # Examples
///
/// ```
/// use core::num::NonZero;
/// use kernel::math64::div_u64_rem;
///
/// let (quot, rem) = div_u64_rem(1_500_000_000, NonZero::new(1_000_000_000).unwrap());
/// assert_eq!((quot, rem), (1, 500_000_000));
/// ```
#[inline]
pub fn div_u64_rem(dividend: u64, divisor: NonZero<u32>) -> (u64, u32) {
    let mut rem = 0;

    // SAFETY: The divisor is nonzero, as `div_u64_rem()` requires, and `rem` points to a
    // live `u32`.
    let quot = unsafe { bindings::div_u64_rem(dividend, divisor.get(), &mut rem) };

    (quot, rem)
}
