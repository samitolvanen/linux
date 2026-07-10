// SPDX-License-Identifier: GPL-2.0

//! Kernel virtual mapping cache maintenance.
//!
//! C header: [`include/linux/highmem.h`](srctree/include/linux/highmem.h)

use crate::{
    bindings,
    prelude::*, //
};

/// Flushes CPU caches for a kernel virtual mapping before a device reads the underlying pages.
///
/// This wraps `flush_kernel_vmap_range()`. On architectures with virtually indexed caches it
/// writes back dirty cache lines of the alias mapping at `[addr, addr + size)` so that DMA from
/// the underlying pages observes CPU writes made through the mapping. On other architectures it
/// is a no-op.
///
/// # Safety
///
/// `[addr, addr + size)` must be a valid kernel virtual mapping for the duration of this call.
#[inline]
pub unsafe fn flush_kernel_vmap_range(addr: *mut c_void, size: usize) {
    let mut offset = 0;
    while offset < size {
        let len = usize::min(size - offset, c_int::MAX as usize);
        // SAFETY: `[addr + offset, addr + offset + len)` lies within the valid mapping
        // guaranteed by the caller, and `len` fits in `c_int` by construction.
        unsafe { bindings::flush_kernel_vmap_range(addr.byte_add(offset), len as c_int) };
        offset += len;
    }
}

/// Invalidates CPU caches for a kernel virtual mapping after a device wrote the underlying pages.
///
/// This wraps `invalidate_kernel_vmap_range()`. On architectures with virtually indexed caches
/// it discards cache lines of the alias mapping at `[addr, addr + size)` so that CPU reads
/// through the mapping observe data written by DMA to the underlying pages. On other
/// architectures it is a no-op.
///
/// # Safety
///
/// `[addr, addr + size)` must be a valid kernel virtual mapping for the duration of this call.
#[inline]
pub unsafe fn invalidate_kernel_vmap_range(addr: *mut c_void, size: usize) {
    let mut offset = 0;
    while offset < size {
        let len = usize::min(size - offset, c_int::MAX as usize);
        // SAFETY: `[addr + offset, addr + offset + len)` lies within the valid mapping
        // guaranteed by the caller, and `len` fits in `c_int` by construction.
        unsafe { bindings::invalidate_kernel_vmap_range(addr.byte_add(offset), len as c_int) };
        offset += len;
    }
}
