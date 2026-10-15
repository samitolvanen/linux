// SPDX-License-Identifier: GPL-2.0

//! Memory reclaim.
//!
//! C header: [`include/linux/swap.h`](srctree/include/linux/swap.h)

use crate::bindings;

/// Returns the number of free pages in swap space.
///
/// Shrinkers that free memory by writing it to swap can use this to check whether swap space is
/// available.
#[inline]
pub fn nr_swap_pages() -> isize {
    // SAFETY: `get_nr_swap_pages()` has no preconditions.
    unsafe { bindings::get_nr_swap_pages() }
}
