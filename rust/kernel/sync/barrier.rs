// SPDX-License-Identifier: GPL-2.0

//! Memory barriers.
//!
//! These primitives have the same semantics as their C counterparts: and the precise definitions
//! of semantics can be found at [`LKMM`].
//!
//! [`LKMM`]: srctree/tools/memory-model/

/// A compiler barrier.
///
/// A barrier that prevents compiler from reordering memory accesses across the barrier.
#[inline(always)]
pub(crate) fn barrier() {
    // By default, Rust inline asms are treated as being able to access any memory or flags, hence
    // it suffices as a compiler barrier.
    //
    // SAFETY: An empty asm block.
    unsafe { core::arch::asm!("") };
}

/// A full memory barrier.
///
/// A barrier that prevents compiler and CPU from reordering memory accesses across the barrier.
#[inline(always)]
pub fn smp_mb() {
    if cfg!(CONFIG_SMP) {
        // SAFETY: `smp_mb()` is safe to call.
        unsafe { bindings::smp_mb() };
    } else {
        barrier();
    }
}

/// A write-write memory barrier.
///
/// A barrier that prevents compiler and CPU from reordering memory write accesses across the
/// barrier.
#[inline(always)]
pub fn smp_wmb() {
    if cfg!(CONFIG_SMP) {
        // SAFETY: `smp_wmb()` is safe to call.
        unsafe { bindings::smp_wmb() };
    } else {
        barrier();
    }
}

/// A read-read memory barrier.
///
/// A barrier that prevents compiler and CPU from reordering memory read accesses across the
/// barrier.
#[inline(always)]
pub fn smp_rmb() {
    if cfg!(CONFIG_SMP) {
        // SAFETY: `smp_rmb()` is safe to call.
        unsafe { bindings::smp_rmb() };
    } else {
        barrier();
    }
}

/// A write-write memory barrier suitable for ordering device-visible stores.
///
/// Unlike [`smp_wmb`], `wmb` orders prior CPU stores ahead of subsequent
/// stores to memory observed by external agents, including device DMA and
/// non-coherent regions, regardless of `CONFIG_SMP`. Use it when publishing
/// data into a shared buffer (for example, a GPU command-stream ringbuffer)
/// before signalling the device.
#[inline(always)]
pub fn wmb() {
    // SAFETY: `wmb()` is safe to call.
    unsafe { bindings::wmb() };
}
