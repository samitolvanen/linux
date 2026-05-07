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

pub(crate) struct GpuIrq {
    iomem: Arc<Devres<IoMem>>,
    power_on_wait: Arc<Wait<bool>>,
}

pub(crate) fn gpu_irq_init<'a>(
    tdev: ARef<TyrDrmDevice>,
    pdev: &'a platform::Device<kernel::device::Bound>,
    iomem: Arc<Devres<IoMem>>,
    power_on_wait: Arc<Wait<bool>>,
) -> Result<impl PinInit<ThreadedRegistration<TyrIrq<GpuIrq>>, Error> + 'a> {
    // SAFETY: pdev is a bound device.
    let dev = unsafe { pdev.as_ref().as_bound() };
    let io = iomem.access(dev)?;
    io.write_reg(gpu_control::GPU_IRQ_MASK::from_raw(u32::MAX));

    let irq_type = GpuIrq {
        iomem: iomem.clone(),
        power_on_wait,
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
        u32::MAX
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
