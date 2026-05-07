// SPDX-License-Identifier: GPL-2.0 or MIT

//! VMs created by userspace are placed in a pool so they can be found by other
//! VM ioctls like VM_BIND or VM_DESTROY.

use core::sync::atomic::AtomicUsize;

use kernel::{
    prelude::*,
    sync::Arc,
    types::ARef,
    xarray,
    xarray::XArray, //
};

use super::{
    Vm,
    VmLayout, //
};
use crate::driver::TyrDrmDevice;

/// The pool for user VMs.
pub(crate) struct Pool {
    xa: Pin<KBox<XArray<Arc<Vm>>>>,
    free_index: AtomicUsize,
}

impl Pool {
    pub(crate) fn create() -> Result<Self> {
        let xa = KBox::pin_init(XArray::new(xarray::AllocKind::Alloc1), GFP_KERNEL)?;

        Ok(Self {
            xa,
            free_index: AtomicUsize::new(1),
        })
    }

    pub(crate) fn create_vm(&self, tdev: &ARef<TyrDrmDevice>, layout: VmLayout) -> Result<usize> {
        let kernel_va_range = layout.kernel.clone();

        let vm = Vm::new(
            &tdev.pdev,
            &**tdev,
            tdev.mmu.as_arc_borrow(),
            tdev.iomem.as_arc_borrow(),
            kernel_va_range,
        )?;

        let index = self
            .free_index
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        let xa = self.xa.as_ref();
        let mut guard = xa.lock();
        guard.store(index, vm, GFP_KERNEL).map_err(|_| EINVAL)?;

        Ok(index)
    }

    pub(crate) fn get_vm(self: Pin<&Self>, index: usize) -> Option<Arc<Vm>> {
        let xa = self.xa.as_ref();
        let guard = xa.lock();
        let vm = guard.get(index)?;
        Some(vm.into())
    }

    pub(crate) fn destroy_vm(self: Pin<&Self>, index: usize) -> Result {
        let xa = self.xa.as_ref();
        let vm = xa.lock().remove(index).ok_or(EINVAL)?;

        vm.kill();
        Ok(())
    }

    /// Destroy all VMs in the pool.
    ///
    /// This is called when the file is being closed to ensure all VMs
    /// are properly unmapped before being dropped.
    pub(crate) fn destroy_all(self: Pin<&Self>) -> Result {
        let max_index = self.free_index.load(core::sync::atomic::Ordering::Relaxed);

        // Try to destroy all possible VMs from 0 to free_index, as there is no
        // iterator implementation in xarray.rs.
        for index in 0..max_index {
            if let Ok(_) = self.destroy_vm(index) {
                pr_info!("Destroyed VM at index {}\n", index);
            }
        }

        Ok(())
    }
}
