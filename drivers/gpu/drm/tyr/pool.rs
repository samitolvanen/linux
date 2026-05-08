// SPDX-License-Identifier: GPL-2.0 or MIT

//! Shared XArray-backed pool for file-owned Tyr objects.
//!
//! This factors the common allocate/get/remove bookkeeping used by the VM pool
//! and future file-scoped pools without forcing object-specific cleanup policy.

use core::sync::atomic::{AtomicUsize, Ordering};

use kernel::{prelude::*, sync::Arc, xarray, xarray::XArray};

pub(crate) struct Pool<T: 'static> {
    xa: Pin<KBox<XArray<Arc<T>>>>,
    free_index: AtomicUsize,
}

impl<T: 'static> Pool<T> {
    pub(crate) fn create() -> Result<Self> {
        let xa = KBox::pin_init(XArray::new(xarray::AllocKind::Alloc1), GFP_KERNEL)?;

        Ok(Self {
            xa,
            free_index: AtomicUsize::new(1),
        })
    }

    pub(crate) fn insert(&self, value: Arc<T>) -> Result<usize> {
        let index = self.free_index.fetch_add(1, Ordering::Relaxed);

        let xa = self.xa.as_ref();
        let mut guard = xa.lock();
        guard.store(index, value, GFP_KERNEL).map_err(|_| EINVAL)?;

        Ok(index)
    }

    pub(crate) fn get(&self, index: usize) -> Option<Arc<T>> {
        let xa = self.xa.as_ref();
        let guard = xa.lock();
        let value = guard.get(index)?;

        Some(value.into())
    }

    pub(crate) fn for_each<F>(&self, mut f: F) -> Result
    where
        F: FnMut(usize, Arc<T>) -> Result,
    {
        for index in 1..self.index_upper_bound() {
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

    pub(crate) fn index_upper_bound(&self) -> usize {
        self.free_index.load(Ordering::Relaxed)
    }
}
