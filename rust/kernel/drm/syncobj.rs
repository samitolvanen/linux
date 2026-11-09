// SPDX-License-Identifier: GPL-2.0 OR MIT

//! DRM Sync Objects
//!
//! C header: [`include/drm/drm_syncobj.h`](../../../../include/drm/drm_syncobj.h)

use core::{marker::PhantomData, ptr::NonNull};

use crate::{
    bindings,
    dma_buf::{dma_fence_chain::FenceChain, Fence},
    drm,
    error::Result,
    prelude::*,
    sync::aref::ARef,
};

use super::Driver;

/// A DRM Sync Object
///
/// # Invariants
///
/// `ptr` is a valid pointer to a `drm_syncobj` and we own a reference to it.
pub struct SyncObj<T: Driver> {
    ptr: *mut bindings::drm_syncobj,
    phantom: PhantomData<T>,
}

impl<T: drm::Driver> SyncObj<T> {
    /// Looks up a sync object by its handle for a given `File`.
    pub fn lookup_handle(file: &drm::File<T::File>, handle: u32) -> Result<SyncObj<T>> {
        // SAFETY: The arguments are valid per the type invariants.
        let ptr = unsafe { bindings::drm_syncobj_find(file.as_raw().cast(), handle) };

        if ptr.is_null() {
            Err(ENOENT)
        } else {
            Ok(SyncObj {
                ptr,
                phantom: PhantomData,
            })
        }
    }

    /// Returns the DMA fence associated with this sync object, if any.
    pub fn fence_get(&self) -> Option<ARef<Fence>> {
        // SAFETY: `self.ptr` is valid per the type invariant.
        let fence = NonNull::new(unsafe { bindings::drm_syncobj_fence_get(self.ptr) })?;

        // SAFETY: `drm_syncobj_fence_get` acquired an additional reference, which
        // the `ARef` takes over. `Fence` is a transparent wrapper of a
        // `struct dma_fence`.
        Some(unsafe { ARef::from_raw(fence.cast()) })
    }

    /// Finds the fence at a specific timeline point for this sync object.
    pub fn find_fence(
        file: &drm::File<T::File>,
        handle: u32,
        point: u64,
        flags: u64,
    ) -> Result<Option<ARef<Fence>>> {
        let mut fence = core::ptr::null_mut();

        // SAFETY: The arguments are valid per the type invariants.
        let ret = unsafe {
            bindings::drm_syncobj_find_fence(file.as_raw().cast(), handle, point, flags, &mut fence)
        };

        if ret != 0 {
            return Err(Error::from_errno(ret));
        }

        let Some(fence) = NonNull::new(fence) else {
            return Ok(None);
        };

        // SAFETY: `drm_syncobj_find_fence` acquired an additional reference,
        // which the `ARef` takes over. `Fence` is a transparent wrapper of a
        // `struct dma_fence`.
        Ok(Some(unsafe { ARef::from_raw(fence.cast()) }))
    }

    /// Replaces the DMA fence with a new one, or removes it if `fence` is `None`.
    pub fn replace_fence(&self, fence: Option<&Fence>) {
        // SAFETY: The arguments are valid per the respective type invariants.
        unsafe {
            bindings::drm_syncobj_replace_fence(
                self.ptr,
                fence.map_or(core::ptr::null_mut(), |fence| fence.as_raw()),
            )
        };
    }

    /// Adds a new timeline point to the sync object.
    pub fn add_point(&self, chain: FenceChain, fence: &Fence, point: u64) {
        // SAFETY: The arguments are valid per the respective type invariants, and
        // this transfers ownership of `chain` to the DRM core.
        unsafe {
            bindings::drm_syncobj_add_point(self.ptr, chain.into_raw(), fence.as_raw(), point)
        };
    }
}

impl<T: Driver> Drop for SyncObj<T> {
    fn drop(&mut self) {
        // SAFETY: We own one reference to this sync object.
        unsafe { bindings::drm_syncobj_put(self.ptr) };
    }
}

impl<T: Driver> Clone for SyncObj<T> {
    fn clone(&self) -> Self {
        // SAFETY: `ptr` is valid per the type invariant and we own a reference.
        unsafe { bindings::drm_syncobj_get(self.ptr) };
        SyncObj {
            ptr: self.ptr,
            phantom: PhantomData,
        }
    }
}

// SAFETY: `drm_syncobj` operations are internally synchronized.
unsafe impl<T: Driver> Sync for SyncObj<T> {}
// SAFETY: `drm_syncobj` operations are internally synchronized.
unsafe impl<T: Driver> Send for SyncObj<T> {}
