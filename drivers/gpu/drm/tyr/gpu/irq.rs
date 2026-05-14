// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU IRQ handler.
//!
//! The GPU interrupt line reports GPU-level faults, the soft-reset
//! completion event, and the power-changed events used by the L2
//! power-on wait.

use kernel::{
    c_str,
    device::{
        Bound,
        Device, //
    },
    devres::Devres,
    io::Io,
    irq::ThreadedRegistration,
    platform,
    prelude::*,
    sync::{
        aref::ARef,
        Arc, //
    },
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
    },
    wait::Wait, //
};

/// Returns the bitmask for the GPU interrupts the driver actively handles.
///
/// This selects the GPU faults, the protected-mode fault, the
/// reset-completed event raised at the end of a soft reset, and the
/// power-changed events used by the L2 power-on wait. Other GPU IRQ
/// sources are left masked so the driver does not have to ack them.
pub(crate) fn gpu_interrupts_mask() -> u32 {
    gpu_control::GPU_IRQ_MASK::zeroed()
        .with_gpu_fault(true)
        .with_gpu_protected_fault(true)
        .with_reset_completed(true)
        .with_power_changed_single(true)
        .with_power_changed_all(true)
        .into_raw()
}

pub(crate) struct GpuIrq {
    iomem: Arc<Devres<IoMem>>,
    power_on_wait: Arc<Wait>,
    /// Cached value of [`gpu_interrupts_mask`] so the per-interrupt
    /// `mask()` does not rebuild it on every call.
    mask: u32,
}

pub(crate) fn gpu_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<Bound>,
    iomem: Arc<Devres<IoMem>>,
    power_on_wait: Arc<Wait>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<GpuIrq>>, Error> + 'a> {
    let mask = gpu_interrupts_mask();
    let io = iomem.access(pdev.as_ref())?;
    // Drop any latched IRQs from a previous probe.
    io.write_reg(gpu_control::GPU_IRQ_CLEAR::from_raw(u32::MAX));
    io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(mask));

    let irq_type = GpuIrq {
        iomem: iomem.clone(),
        power_on_wait,
        mask,
    };

    TyrIrq::request(pdev, tdev, c_str!("gpu"), irq_type)
}

impl TyrIrqTrait for GpuIrq {
    fn read_status(&self, dev: &Device<Bound>) -> u32 {
        self.iomem
            .access(dev)
            .map(|io| io.read(gpu_control::GPU_IRQ_STATUS).into_raw())
            .unwrap_or_default()
    }

    fn disable_all(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(0));
        }
    }

    fn reenable(&self, dev: &Device<Bound>) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(self.mask));
        }
    }

    fn read_raw_status(&self, dev: &Device<Bound>) -> u32 {
        self.iomem
            .access(dev)
            .map(|io| io.read(gpu_control::GPU_IRQ_RAWSTAT).into_raw())
            .unwrap_or_default()
    }

    fn clear_status(&self, dev: &Device<Bound>, status: u32) {
        if let Ok(io) = self.iomem.access(dev) {
            io.write_reg(gpu_control::GPU_IRQ_CLEAR::from_raw(status));
        }
    }

    fn mask(&self) -> u32 {
        self.mask
    }

    fn handle(&self, _tdev: &TyrDrmDevice, status: u32) {
        let status_reg = gpu_control::GPU_IRQ_STATUS::from_raw(status);

        if status_reg.gpu_fault() || status_reg.gpu_protected_fault() {
            if let Some(io) = self.iomem.try_access() {
                let fault_status = io.read(gpu_control::GPU_FAULTSTATUS).into_raw();
                let fault_addr = join_u64(
                    io.read(gpu_control::GPU_FAULTADDRESS_LO).into_raw(),
                    io.read(gpu_control::GPU_FAULTADDRESS_HI).into_raw(),
                );
                pr_err!(
                    "GPU fault: status=0x{:08x} address=0x{:016x} protected={}\n",
                    fault_status,
                    fault_addr,
                    status_reg.gpu_protected_fault()
                );
                // Re-arm the GPU fault latch so subsequent faults can fire
                // again. Without this the FAULTSTATUS register stays
                // asserted and no further GPU_FAULT interrupts are raised.
                io.write_reg(gpu_control::GPU_COMMAND::clear_fault());
            }
        }

        if status_reg.reset_completed()
            || status_reg.power_changed_single()
            || status_reg.power_changed_all()
        {
            self.power_on_wait.notify_all();
        }
    }
}
