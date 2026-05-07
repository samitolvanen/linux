// SPDX-License-Identifier: GPL-2.0 OR MIT

//! GPUVM execution token helpers for reservation-object updates.

use kernel::{
    bindings::drm_gpuvm_exec,
    dma_buf::dma_fence::PublicDmaFence,
    drm::gpuvm::{
        DriverGpuVm,
        GpuVm,
    },
    error::{
        Result,
        to_result,
    },
    prelude::*,
};

pub(crate) struct ExecToken<'a, T: DriverGpuVm> {
    _gpuvm: &'a GpuVm<T>,
    vm_exec: Pin<KBox<drm_gpuvm_exec>>,
    #[expect(dead_code)]
    pub(crate) num_slots: u32,
}

impl<'a, T: DriverGpuVm> ExecToken<'a, T> {
    pub(crate) fn prepare(gpuvm: &'a GpuVm<T>, num_slots: u32) -> Result<Self> {
        const DRM_EXEC_INTERRUPTIBLE_WAIT: u32 = 0;

        let mut guard = core::mem::ManuallyDrop::new(Self {
            _gpuvm: gpuvm,
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

        // SAFETY: `vm_exec` is initialized above and points at a live GPUVM.
        to_result(unsafe { kernel::bindings::drm_gpuvm_exec_lock(&mut *guard.vm_exec) })?;

        Ok(core::mem::ManuallyDrop::into_inner(guard))
    }

    pub(crate) fn resv_add_fence(
        &mut self,
        fence: &PublicDmaFence,
        private_usage: u32,
        extobj_usage: u32,
    ) {
        // SAFETY: `vm_exec` stays locked for the lifetime of the token and `fence` is live.
        unsafe {
            kernel::bindings::drm_gpuvm_resv_add_fence(
                self.vm_exec.vm,
                core::ptr::from_ref(&self.vm_exec.exec).cast_mut(),
                fence.raw(),
                private_usage,
                extobj_usage,
            )
        }
    }
}

impl<T: DriverGpuVm> Drop for ExecToken<'_, T> {
    fn drop(&mut self) {
        // SAFETY: `prepare()` acquired the exec lock, and `drm_gpuvm_exec_unlock()` is an inline
        // wrapper around `drm_exec_fini()` in this tree.
        unsafe {
            kernel::bindings::drm_exec_fini(&mut self.vm_exec.exec);
        }
    }
}