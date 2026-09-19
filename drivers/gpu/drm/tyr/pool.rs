// SPDX-License-Identifier: GPL-2.0 or MIT

//! Shared XArray-backed pool for file-owned Tyr objects.
//!
//! This factors the common allocate/get/remove bookkeeping used by the VM pool
//! and future file-scoped pools without forcing object-specific cleanup policy.

use kernel::{
    prelude::*,
    sync::{
        atomic::{
            Atomic,
            Relaxed, //
        },
        Arc, //
    },
    xarray,
    xarray::XArray, //
};

/// Lowest index a pool hands out. The XArray is `Alloc1`, so index 0 is
/// never allocated.
const MIN_INDEX: u32 = 1;

pub(crate) struct Pool<T: 'static> {
    xa: Pin<KBox<XArray<Arc<T>>>>,
    max_index: u32,
    next_index: Atomic<u32>,
}

impl<T: 'static> Pool<T> {
    /// Creates a pool that hands out indices in `1..=max_index`.
    pub(crate) fn create(max_index: u32) -> Result<Self> {
        let xa = KBox::pin_init(XArray::new(xarray::AllocKind::Alloc1), GFP_KERNEL)?;

        Ok(Self {
            xa,
            max_index,
            next_index: Atomic::new(MIN_INDEX),
        })
    }

    /// Stores `value` at the next free index, wrapping within the pool range.
    ///
    /// Returns `EBUSY` when every index in the range is taken.
    pub(crate) fn insert(&self, value: Arc<T>) -> Result<usize> {
        let xa = self.xa.as_ref();
        let mut guard = xa.lock();

        let mut next = self.next_index.load(Relaxed);
        let index = match guard.alloc_cyclic(
            value,
            xarray::XaLimit::new(MIN_INDEX, self.max_index),
            &mut next,
            GFP_KERNEL,
        ) {
            Ok(index) => index,
            Err(e) => {
                // Dropping the last reference to the value can sleep.
                drop(guard);
                return Err(e.error);
            }
        };
        self.next_index.store(next, Relaxed);

        Ok(index)
    }

    pub(crate) fn get(&self, index: usize) -> Option<Arc<T>> {
        let xa = self.xa.as_ref();
        let guard = xa.lock();
        let value = guard.get(index)?;

        Some(value.into())
    }

    /// Calls `f` for every index in the pool that holds a value.
    ///
    /// The pool lock is not held while `f` runs, so entries can be added or
    /// removed concurrently, including by `f` itself.
    pub(crate) fn for_each<F>(&self, mut f: F) -> Result
    where
        F: FnMut(usize, Arc<T>) -> Result,
    {
        for index in MIN_INDEX as usize..=self.max_index as usize {
            if let Some(value) = self.get(index) {
                f(index, value)?;
            }
        }

        Ok(())
    }

    pub(crate) fn remove(&self, index: usize) -> Result<Arc<T>> {
        let xa = self.xa.as_ref();
        let mut guard = xa.lock();
        let value = guard.remove(index).ok_or(EINVAL)?;

        Ok(value)
    }
}
