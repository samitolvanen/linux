// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU IRQ handler.
//!
//! The GPU interrupt line reports GPU-level faults. The soft-reset
//! completion and the L2 power-changed events are also sources on this
//! line, but stay masked because the driver polls for them instead.

use kernel::{
    device::Bound,
    io::{
        mem::DevresIoMem,
        Io, //
    },
    irq::ThreadedRegistration,
    platform,
    prelude::*,
    sizes::SZ_2M,
    sync::{
        aref::ARef,
        Arc, //
    }, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice, //
    },
    irq::{
        TyrIrq,
        TyrIrqTrait, //
    },
    regs::{
        gpu_control,
        join_u64, //
    }, //
};

/// Returns the GPU IRQ sources the driver services.
///
/// This selects the GPU fault and the protected-mode fault. Other GPU IRQ
/// sources are left masked so the driver does not have to ack them.
///
/// `reset_completed` is left masked. `GPU_IRQ_RAWSTAT` latches the bit
/// regardless of the mask, so `soft_reset`'s poll owns it on every path.
/// No IRQ handler can clear the bit before the poll observes it.
fn gpu_irq_sources() -> gpu_control::GPU_IRQ_MASK {
    gpu_control::GPU_IRQ_MASK::zeroed()
        .with_gpu_fault(true)
        .with_gpu_protected_fault(true)
}

pub(crate) struct GpuIrq;

/// Clears the latched GPU IRQs the driver services and unmasks them.
pub(crate) fn gpu_irq_enable(io: &IoMem<'_>) {
    let sources = gpu_irq_sources();

    io.write_reg(gpu_control::GPU_IRQ_CLEAR::from_raw(sources.into_raw()));
    io.write_reg(sources);
}

/// Masks all GPU IRQ sources.
pub(crate) fn gpu_irq_disable(io: &IoMem<'_>) {
    io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(0));
}

/// Registers the GPU IRQ handler with the sources masked.
///
/// # Safety
///
/// Callers must not `mem::forget()` the resulting registration or otherwise prevent its
/// `Drop` implementation from running.
pub(crate) unsafe fn gpu_irq_init<'drm>(
    pdev: &'drm platform::Device<Bound>,
    tdev: ARef<TyrDrmDevice>,
    iomem: Arc<DevresIoMem<SZ_2M>>,
) -> Result<impl PinInit<ThreadedRegistration<'drm, TyrIrq<'drm, GpuIrq>>, Error> + 'drm> {
    // The caller unmasks the sources once the handler is registered.
    iomem
        .access(pdev.as_ref())?
        .write_reg(gpu_control::GPU_IRQ_MASK::from_raw(0));

    // SAFETY: The caller guarantees that the registration is not leaked.
    Ok(unsafe { TyrIrq::request(pdev, tdev, c"gpu", iomem, GpuIrq) })
}

impl TyrIrqTrait for GpuIrq {
    fn read_status(&self, io: &IoMem<'_>) -> u32 {
        io.read(gpu_control::GPU_IRQ_STATUS).into_raw()
    }

    fn disable_all(&self, io: &IoMem<'_>) {
        io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(0));
    }

    fn reenable(&self, io: &IoMem<'_>) {
        io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(self.mask()));
    }

    fn read_raw_status(&self, io: &IoMem<'_>) -> u32 {
        io.read(gpu_control::GPU_IRQ_RAWSTAT).into_raw()
    }

    fn clear_status(&self, io: &IoMem<'_>, status: u32) {
        io.write_reg(gpu_control::GPU_IRQ_CLEAR::from_raw(status));
    }

    fn mask(&self) -> u32 {
        gpu_irq_sources().into_raw()
    }

    fn handle(&self, tdev: &TyrDrmDevice, io: &IoMem<'_>, status: u32) {
        let status_reg = gpu_control::GPU_IRQ_STATUS::from_raw(status);

        if status_reg.gpu_fault() || status_reg.gpu_protected_fault() {
            let fault_status = io.read(gpu_control::GPU_FAULTSTATUS).into_raw();
            let fault_addr = join_u64(
                io.read(gpu_control::GPU_FAULTADDRESS_LO).into_raw(),
                io.read(gpu_control::GPU_FAULTADDRESS_HI).into_raw(),
            );
            dev_err!(
                tdev.as_ref(),
                "GPU fault: status=0x{:08x} address=0x{:016x} protected={}\n",
                fault_status,
                fault_addr,
                status_reg.gpu_protected_fault()
            );
        }
    }
}
