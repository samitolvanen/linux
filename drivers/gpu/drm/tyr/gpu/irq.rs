// SPDX-License-Identifier: GPL-2.0 or MIT

//! GPU IRQ handler.

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
    sync::Arc,
    types::ARef, //
};

use crate::{
    driver::{
        IoMem,
        TyrDrmDevice,
        TyrIrq,
        TyrIrqTrait, //
    },
    regs::gpu_control,
    wait::Wait, //
};

/// Returns the bitmask for the GPU interrupts the driver actively handles.
///
/// This selects the GPU faults, the protected-mode fault, the
/// reset-completed event used by [`issue_soft_reset`], and the
/// power-changed events used by the L2 power-on wait.  Other GPU IRQ
/// sources are left masked so the driver does not have to ack them.
///
/// [`issue_soft_reset`]: crate::driver::issue_soft_reset
pub(crate) fn gpu_interrupts_mask() -> u32 {
    gpu_control::GPU_IRQ_STATUS::from_raw(0)
        .with_gpu_fault(true)
        .with_gpu_protected_fault(true)
        .with_reset_completed(true)
        .with_power_changed_single(true)
        .with_power_changed_all(true)
        .into_raw()
}

pub(crate) struct GpuIrq {
    iomem: Arc<Devres<IoMem>>,
    power_on_wait: Arc<Wait<bool>>,
    /// Cached value of [`gpu_interrupts_mask`] so the per-interrupt
    /// `mask()` does not rebuild it on every call.
    mask: u32,
}

pub(crate) fn gpu_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<kernel::device::Bound>,
    iomem: Arc<Devres<IoMem>>,
    power_on_wait: Arc<Wait<bool>>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<GpuIrq>>, Error> + 'a> {
    let irq_type = GpuIrq {
        iomem: iomem.clone(),
        power_on_wait,
        mask: gpu_interrupts_mask(),
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
            io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(self.mask()));
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

    fn handle(&self, _: &TyrDrmDevice, status: u32) {
        let status_reg = gpu_control::GPU_IRQ_STATUS::from_raw(status);
        if status_reg.reset_completed()
            || status_reg.power_changed_single()
            || status_reg.power_changed_all()
        {
            let _ = self.power_on_wait.with_locked_data(|powered_on| {
                *powered_on = true;
                Ok(())
            });

            self.power_on_wait.notify_all();
        }
    }
}

impl GpuIrq {
    /// Enables the GPU interrupts in hardware.
    ///
    /// Clears any latched bits in `GPU_IRQ_RAWSTAT` left over from a
    /// previous probe before unmasking, then writes
    /// [`gpu_interrupts_mask`] to `GPU_IRQ_MASK` so only the interrupts
    /// the driver handles can fire.
    pub(crate) fn enable_hardware(dev: &Device<Bound>, iomem: &Devres<IoMem>) -> Result {
        let io = iomem.access(dev)?;
        // Drop any latched IRQs from a previous probe.
        io.write_reg(gpu_control::GPU_IRQ_CLEAR::from_raw(u32::MAX));
        io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(gpu_interrupts_mask()));
        Ok(())
    }
}
