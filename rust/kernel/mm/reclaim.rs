// SPDX-License-Identifier: GPL-2.0

//! Memory reclaim.
//!
//! C headers: [`include/linux/swap.h`](srctree/include/linux/swap.h) and
//! [`include/linux/sched/mm.h`](srctree/include/linux/sched/mm.h)

use crate::{
    alloc::Flags,
    bindings,
    types::NotThreadSafe, //
};

/// Returns the number of free pages in swap space.
///
/// Shrinkers that free memory by writing it to swap can use this to check whether swap space is
/// available.
#[inline]
pub fn nr_swap_pages() -> isize {
    // SAFETY: `get_nr_swap_pages()` has no preconditions.
    unsafe { bindings::get_nr_swap_pages() }
}

/// A scope in which lockdep treats the current task as if it were reclaiming memory.
///
/// Taking a lock inside the scope tells lockdep that memory reclaim may take it, so that lockdep
/// reports allocations made while the lock is held. Code inside the scope must not allocate
/// memory with flags that allow reclaim. Without `CONFIG_LOCKDEP`, the scope does nothing.
///
/// # Examples
///
/// ```
/// use kernel::{
///     mm::reclaim::FsReclaimGuard,
///     prelude::*,
///     sync::Mutex, //
/// };
///
/// fn prime_lockdep(lock: &Mutex<()>) {
///     let _reclaim = FsReclaimGuard::new(GFP_KERNEL);
///     drop(lock.lock());
/// }
/// ```
#[must_use = "the scope ends immediately when the guard is unused"]
pub struct FsReclaimGuard {
    flags: Flags,
    _not_send: NotThreadSafe,
}

impl FsReclaimGuard {
    /// Enters a reclaim scope for an allocation with `flags`.
    #[inline]
    pub fn new(flags: Flags) -> Self {
        // SAFETY: `fs_reclaim_acquire()` only updates lockdep state, and the guard releases it on
        // this task.
        unsafe { bindings::fs_reclaim_acquire(flags.as_raw()) };

        Self {
            flags,
            _not_send: NotThreadSafe,
        }
    }
}

impl Drop for FsReclaimGuard {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: `new()` called `fs_reclaim_acquire()` with the same flags on this task.
        unsafe { bindings::fs_reclaim_release(self.flags.as_raw()) };
    }
}
