// SPDX-License-Identifier: GPL-2.0 or MIT

//! VMs created by userspace are placed in a pool so they can be find by other
//! VM ioctls like VM_BIND or VM_DESTROY.

use core::sync::atomic::AtomicUsize;

use kernel::devres::Devres;
use kernel::io::mem::IoMem;
use kernel::prelude::*;
use kernel::sync::Arc;
use kernel::sync::Mutex;
use kernel::types::ARef;
use kernel::xarray;
use kernel::xarray::XArray;

use crate::driver::TyrDevice;
use crate::mmu::vm::Vm;
use crate::mmu::vm::VmLayout;

/// The pool for user VMs.
pub(crate) struct Pool {
    xa: Pin<KBox<XArray<Arc<Mutex<Vm>>>>>,
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

    pub(crate) fn create_vm(&self, tdev: &ARef<TyrDevice>, layout: VmLayout) -> Result<usize> {
        let auto_kernel_va = layout.kernel.clone();

        let vm = {
            tdev.with_locked_mmu(|mmu| {
                mmu.create_vm(
                    tdev,
                    &tdev.pdev,
                    &tdev.gpu_info,
                    false,
                    layout,
                    auto_kernel_va,
                )
            })
        }?;

        let index = self
            .free_index
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);

        let xa = self.xa.as_ref();
        let mut guard = xa.lock();
        guard.store(index, vm, GFP_KERNEL).map_err(|_| EINVAL)?;

        Ok(index)
    }

    pub(crate) fn get_vm(self: Pin<&Self>, index: usize) -> Option<Arc<Mutex<Vm>>> {
        let xa = self.xa.as_ref();
        let guard = xa.lock();
        let vm = guard.get(index)?;
        Some(vm.into())
    }

    pub(crate) fn destroy_vm(self: Pin<&Self>, index: usize, iomem: Arc<Devres<IoMem>>) -> Result {
        let xa = self.xa.as_ref();
        let vm = xa.lock().remove(index).ok_or(EINVAL)?;

        let mut vm = vm.lock();
        vm.destroyed = true;
        vm.unmap_all(iomem)
    }
}
