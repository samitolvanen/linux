// SPDX-License-Identifier: GPL-2.0 OR MIT

//! VM execution token.

use kernel::bindings;
use kernel::bindings::drm_gpuvm_exec;
use kernel::dma_fence::RawDmaFence;
use kernel::drm::gpuvm::DriverGpuVm;
use kernel::drm::gpuvm::GpuVm;
use kernel::error::to_result;
use kernel::error::Result;
use kernel::prelude::*;

/// A token that ensures that all the objects within the VM are locked and that
/// `num_slots` have been reserved for fences.
pub(crate) struct ExecToken<'a, T: DriverGpuVm> {
    _gpuvm: &'a GpuVm<T>,
    vm_exec: Pin<KBox<drm_gpuvm_exec>>,
    /// The number of slots reserved for fences.
    #[expect(dead_code)]
    pub num_slots: u32,
}

impl<'a, T: DriverGpuVm> ExecToken<'a, T> {
    pub(crate) fn prepare(gpuvm: &'a GpuVm<T>, num_slots: u32) -> Result<Self> {
        // We will probably replace this when the new scheduler debuts anyways,
        // so just hack it for now.
        const DRM_EXEC_INTERRUPTIBLE_WAIT: u32 = 0;
        let mut guard = core::mem::ManuallyDrop::new(Self {
            _gpuvm: gpuvm,
            // vm_exec needs to be pinned, so stick it in a Box.
            vm_exec: KBox::pin_init(
                init!(drm_gpuvm_exec {
                    vm: gpuvm.as_raw(),
                    flags: DRM_EXEC_INTERRUPTIBLE_WAIT,
                    exec: Default::default(),
                    extra: Default::default(),
                    num_fences: num_slots,
                }),
                GFP_KERNEL,
            )?,
            num_slots,
        });

        // SAFETY: The object is valid and was initialized above
        to_result(unsafe { bindings::drm_gpuvm_exec_lock(&mut *guard.vm_exec) })?;

        Ok(core::mem::ManuallyDrop::into_inner(guard))
    }

    /// Adds a fence to the private and external buffer object reservations.
    pub(crate) fn resv_add_fence(
        &mut self,
        fence: &dyn RawDmaFence,
        private_usage: u32,
        extobj_usage: u32,
    ) {
        // SAFETY: vm_exec is valid and locked, fence is valid per RawDmaFence contract.
        unsafe {
            bindings::drm_gpuvm_resv_add_fence(
                self.vm_exec.vm,
                &self.vm_exec.exec as *const _ as *mut _,
                fence.raw(),
                private_usage,
                extobj_usage,
            )
        }
    }
}

impl<'a, T: DriverGpuVm> Drop for ExecToken<'a, T> {
    fn drop(&mut self) {
        // SAFETY: We hold the lock, so it's safe to unlock.
        unsafe {
            bindings::drm_gpuvm_exec_unlock(&mut *self.vm_exec);
        }
    }
}
