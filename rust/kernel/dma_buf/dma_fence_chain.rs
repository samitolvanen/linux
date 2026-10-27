// SPDX-License-Identifier: GPL-2.0

//! DMA fence chains.
//!
//! C header: [`include/linux/dma-fence-chain.h`](srctree/include/linux/dma-fence-chain.h)

use core::ptr::NonNull;

use crate::{
    bindings,
    prelude::*, //
};

/// A wrapper around a `dma_fence_chain` object.
///
/// # Invariants
///
/// - `ptr` is a valid, non-null pointer to a dma_fence_chain which we own.
pub struct FenceChain {
    ptr: NonNull<bindings::dma_fence_chain>,
}

impl FenceChain {
    /// Create a new `FenceChain` object.
    pub fn new() -> Result<Self> {
        // SAFETY: This function is safe to call and takes no arguments.
        let ptr = unsafe { bindings::dma_fence_chain_alloc() };

        let ptr = NonNull::new(ptr).ok_or(ENOMEM)?;
        Ok(Self { ptr })
    }

    /// Convert the `FenceChain` into the underlying raw pointer.
    ///
    /// This transfers ownership of the allocation to the caller.
    pub(crate) fn into_raw(self) -> *mut bindings::dma_fence_chain {
        let ptr = self.ptr.as_ptr();
        core::mem::forget(self);
        ptr
    }
}

impl Drop for FenceChain {
    fn drop(&mut self) {
        // SAFETY: We own this dma_fence_chain allocation.
        unsafe { bindings::dma_fence_chain_free(self.ptr.as_ptr()) };
    }
}
